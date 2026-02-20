"""
Scam Detector Module
Analyzes incoming messages to detect potential scam attempts.
"""

import re
from typing import Dict, List, Tuple, Optional
from .patterns import (
    get_scam_patterns, 
    get_urgency_indicators, 
    get_sensitive_data_requests,
    SCAM_TYPES
)


class ScamDetector:
    """Detects and classifies scam messages."""
    
    def __init__(self):
        self.scam_patterns = get_scam_patterns()
        self.urgency_indicators = get_urgency_indicators()
        self.sensitive_requests = get_sensitive_data_requests()
    
    def analyze(self, message: str) -> Dict:
        """
        Analyze a message for scam indicators.
        
        Args:
            message: The incoming message to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        message_lower = message.lower()
        
        # Find matching scam types
        scam_scores = self._calculate_scam_scores(message_lower)
        
        # Check for urgency
        urgency_score, urgency_matches = self._check_urgency(message_lower)
        
        # Check for sensitive data requests
        sensitive_score, sensitive_matches = self._check_sensitive_requests(message_lower)
        
        # Determine the most likely scam type
        top_scam_type, top_score = self._get_top_scam_type(scam_scores)
        
        # Calculate overall confidence
        base_confidence = top_score * 60  # Max 60 from patterns
        urgency_bonus = urgency_score * 20  # Max 20 from urgency
        sensitive_bonus = sensitive_score * 20  # Max 20 from sensitive requests
        
        confidence = min(100, base_confidence + urgency_bonus + sensitive_bonus)
        
        # Compile indicators
        indicators = self._compile_indicators(
            scam_scores, urgency_matches, sensitive_matches
        )
        
        is_scam = confidence >= 40  # Threshold for scam detection
        
        return {
            "is_scam": is_scam,
            "confidence": round(confidence, 2),
            "scam_type": top_scam_type if is_scam else None,
            "indicators": indicators,
            "urgency_detected": len(urgency_matches) > 0,
            "sensitive_data_requested": len(sensitive_matches) > 0,
            "all_scam_scores": scam_scores
        }
    
    def _calculate_scam_scores(self, message: str) -> Dict[str, float]:
        """Calculate scam scores for each scam type."""
        scores = {}
        
        for scam_type, config in self.scam_patterns.items():
            score = 0.0
            keywords = config["keywords"]
            patterns = config["patterns"]
            weight = config["weight"]
            
            # Check keywords (each keyword adds to score)
            keyword_matches = sum(1 for kw in keywords if kw in message)
            keyword_score = min(1.0, keyword_matches / 3)  # Cap at 3 matches
            
            # Check regex patterns
            pattern_matches = sum(
                1 for pattern in patterns 
                if re.search(pattern, message, re.IGNORECASE)
            )
            pattern_score = min(1.0, pattern_matches / 2)  # Cap at 2 matches
            
            # Combine scores with weight
            score = (keyword_score * 0.6 + pattern_score * 0.4) * weight
            scores[scam_type] = round(score, 3)
        
        return scores
    
    def _check_urgency(self, message: str) -> Tuple[float, List[str]]:
        """Check for urgency indicators."""
        matches = [ind for ind in self.urgency_indicators if ind in message]
        score = min(1.0, len(matches) / 2)  # Cap at 2 matches
        return score, matches
    
    def _check_sensitive_requests(self, message: str) -> Tuple[float, List[str]]:
        """Check for sensitive data requests."""
        matches = [req for req in self.sensitive_requests if req in message]
        score = min(1.0, len(matches) / 2)  # Cap at 2 matches
        return score, matches
    
    def _get_top_scam_type(self, scores: Dict[str, float]) -> Tuple[Optional[str], float]:
        """Get the most likely scam type."""
        if not scores:
            return None, 0.0
        
        top_type = max(scores, key=scores.get)
        top_score = scores[top_type]
        
        if top_score < 0.1:  # Minimum threshold
            return None, 0.0
        
        return top_type, top_score
    
    def _compile_indicators(
        self, 
        scam_scores: Dict[str, float],
        urgency_matches: List[str],
        sensitive_matches: List[str]
    ) -> List[str]:
        """Compile all detected indicators."""
        indicators = []
        
        # Add top scam types as indicators
        for scam_type, score in sorted(scam_scores.items(), key=lambda x: x[1], reverse=True):
            if score > 0.1:
                indicators.append(f"{scam_type}_patterns")
        
        # Add urgency indicators
        if urgency_matches:
            indicators.append("urgency_tactics")
        
        if sensitive_matches:
            indicators.append("sensitive_data_request")
        
        return indicators[:5]  # Return top 5 indicators


# Create a default instance
scam_detector = ScamDetector()


def analyze_message(message: str) -> Dict:
    """Convenience function to analyze a message."""
    return scam_detector.analyze(message)

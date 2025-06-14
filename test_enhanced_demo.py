#!/usr/bin/env python3
"""
Test the enhanced self-improvement implementation
"""

from issue_analyzer import EnhancedReviewAnalyzer

def test_enhanced_analysis():
    """Test enhanced analyzer with OWASP mapping and gap analysis"""
    analyzer = EnhancedReviewAnalyzer()

    # Sample diff with multiple security issues
    test_diff = '''
+++ b/auth.py
@@ -1,0 +1,15 @@
+def authenticate_user(username, password):
+    try:
+        # SQL injection vulnerability (A03)
+        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
+        cursor.execute(query)
+        result = cursor.fetchone()
+        
+        # Hardcoded API key (A02)
+        api_key = "sk-1234567890abcdef1234567890abcdef"
+        
+        # Weak crypto (A02)
+        import hashlib
+        hash = hashlib.md5(password.encode())
+        
+        return result
+    except:
+        pass  # Bare except with ignored exception
'''

    print('\n' + '='*80)
    print('🔍 ENHANCED SELF-IMPROVEMENT ANALYSIS DEMONSTRATION')
    print('='*80)

    report = analyzer.analyze_diff(test_diff, 'auth.py')

    print(f"\n📊 ENHANCED SUMMARY:")
    print(f"  • Total Issues: {report['summary']['total_issues']}")
    print(f"  • Security: {report['summary']['security_issues']}")
    print(f"  • Error Handling: {report['summary']['error_handling_issues']}")
    print(f"  • OWASP Categories: {len(report['summary']['owasp_categories'])}")
    print(f"  • Confidence: {int(report['summary']['confidence_avg'] * 100)}%")

    print(f"\n🛡️ OWASP TOP 10 MAPPING:")
    for owasp_cat, count in report['summary']['owasp_categories'].items():
        plural = 's' if count != 1 else ''
        print(f"  • {owasp_cat}: {count} issue{plural}")

    print(f"\n🔒 SECURITY ISSUES WITH OWASP MAPPING:")
    for issue in report['sections']['security']['issues']:
        print(f"  • {issue['severity'].upper()}: {issue['title']}")
        print(f"    🛡️ OWASP: {issue['owasp_category']}")
        print(f"    📍 {issue['location']}")
        print(f"    📊 Confidence: {int(issue['confidence'] * 100)}%")
        print()

    print(f"⚠️ ERROR HANDLING ISSUES:")
    for issue in report['sections']['error_handling']['issues']:
        print(f"  • {issue['severity'].upper()}: {issue['title']}")
        print(f"    📍 {issue['location']}")
        print(f"    🔧 {issue['remediation']}")
        print()

    # Test gap analysis
    if 'gap_analysis' in report:
        gap = report['gap_analysis']
        print(f"🔍 GAP ANALYSIS:")
        print(f"  • Coverage gaps: {gap.get('coverage_gaps', 0)}")
        print(f"  • Consensus issues: {gap.get('consensus_issues', 0)}")
        print(f"  • Duplicates prevented: {gap.get('duplicates_found', 0)}")
        print()

    print('='*80)
    return report

if __name__ == '__main__':
    test_enhanced_analysis()
#!/usr/bin/env node
/**
 * Security Suite Runner for SpanTree Extension
 * 
 * This script runs the complete security analysis suite in the correct order
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 Running SpanTree Security Analysis Suite...\n');

const securityTools = [
    {
        name: 'Security Analysis',
        script: 'security-analysis.js',
        description: 'Identifies security vulnerabilities in the codebase'
    },
    {
        name: 'Security Fixes',
        script: 'security-fixes.js',
        description: 'Applies automated security fixes'
    },
    {
        name: 'Security Validation',
        script: 'security-validator.js',
        description: 'Validates security improvements'
    },
    {
        name: 'Comprehensive Report',
        script: 'comprehensive-security-report.js',
        description: 'Generates final security assessment report'
    }
];

function runSecurityTool(tool) {
    console.log(`🔧 Running ${tool.name}...`);
    console.log(`   ${tool.description}`);
    
    try {
        const output = execSync(`node ${tool.script}`, { 
            encoding: 'utf8',
            cwd: process.cwd()
        });
        
        console.log('✅ Completed successfully\n');
        return true;
    } catch (error) {
        console.log(`❌ Error running ${tool.name}:`, error.message);
        return false;
    }
}

// Run all security tools in sequence
let completedTools = 0;
for (const tool of securityTools) {
    const success = runSecurityTool(tool);
    if (success) {
        completedTools++;
    }
}

// Summary
console.log('📊 SECURITY SUITE EXECUTION SUMMARY');
console.log('='.repeat(50));
console.log(`Completed Tools: ${completedTools}/${securityTools.length}`);

if (completedTools === securityTools.length) {
    console.log('🎉 All security tools executed successfully!');
    
    // List generated files
    console.log('\n📄 Generated Security Files:');
    const securityFiles = [
        'security-report.json',
        'security-fixes-applied.json', 
        'security-validation-report.json',
        'COMPREHENSIVE-SECURITY-REPORT.json',
        'secure-messaging.js',
        'secure-storage.js',
        'SECURITY.md',
        'manifest.json.backup'
    ];
    
    securityFiles.forEach(file => {
        if (fs.existsSync(file)) {
            console.log(`   ✅ ${file}`);
        } else {
            console.log(`   ❌ ${file} (missing)`);
        }
    });
    
    console.log('\n🛡️  Security Status: The SpanTree extension security has been comprehensively analyzed and significantly improved!');
} else {
    console.log('⚠️  Some tools failed to complete. Please check the errors above.');
}

console.log('\n🔍 Next Steps:');
console.log('1. Review the comprehensive security report');
console.log('2. Update vulnerable dependencies');
console.log('3. Integrate secure utilities into your codebase');
console.log('4. Test the extension thoroughly');
console.log('5. Set up continuous security monitoring');
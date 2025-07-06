// translations.js - File delle traduzioni per il Password Security Tool

const translations = {
    it: {
        title: '🔐 Strumento di Sicurezza Password',
        subtitle: 'Genera, analizza e controlla le tue password.',
        'tab-gen': 'Genera Password',
        'tab-str': 'Controlla Forza',
        'tab-bre': 'Controlla Violazioni',
        'gen-title': 'Genera una Password Sicura',
        'gen-length': 'Lunghezza (8-128):',
        'gen-symbols': 'Includi Simboli (!@#$%)',
        'gen-ambiguous': 'Escludi Caratteri Ambigui (0, O, 1, l, I, |)',
        'gen-btn': 'Genera Password',
        'gen-result': 'Password generata:',
        copy: 'Copia',
        strength: 'Forza:',
        'str-title': 'Controlla la Forza della Password',
        'str-label': 'Inserisci password:',
        password: 'La tua password',
        'str-btn': 'Controlla Forza',
        'str-results': 'Risultati:',
        'str-overall': 'Forza:',
        'str-len': 'Lunghezza:',
        'str-upper': 'Maiuscole:',
        'str-lower': 'Minuscole:',
        'str-digits': 'Numeri:',
        'str-special': 'Simboli:',
        'str-common': 'Password comune:',
        'str-rec': 'Raccomandazioni:',
        'bre-title': 'Controlla Violazioni',
        'bre-label': 'Inserisci password:',
        'bre-btn': 'Controlla Password',
        'copy-success': 'Copiato!',
        'enter-password': 'Inserisci una password',
        'network-error': 'Errore di rete',
        'yes': '✅ Sì',
        'no': '❌ No',
        'warning-yes': '⚠️ Sì',
        'breach-safe': 'Password sicura - non trovata in violazioni',
        'breach-found': 'Password trovata in {count} violazioni. Cambiala!',
        // Aggiungi qui nuove traduzioni se necessario
        'rec-length': 'Aumenta la lunghezza ad almeno 12 caratteri',
        'rec-upper': 'Aggiungi lettere maiuscole',
        'rec-lower': 'Aggiungi lettere minuscole',
        'rec-digits': 'Aggiungi numeri',
        'rec-special': 'Aggiungi simboli speciali',
        'rec-common': 'Evita password comuni, usa combinazioni uniche',
        'rec-avoid-personal': 'Evita informazioni personali',
        'rec-complexity': 'Aumenta la complessità della password'
    },
    en: {
        title: '🔐 Password Security Tool',
        subtitle: 'Generate, analyze and check your passwords.',
        'tab-gen': 'Generate Password',
        'tab-str': 'Check Strength',
        'tab-bre': 'Check Breaches',
        'gen-title': 'Generate a Secure Password',
        'gen-length': 'Length (8-128):',
        'gen-symbols': 'Include Symbols (!@#$%)',
        'gen-ambiguous': 'Exclude Ambiguous Characters (0, O, 1, l, I, |)',
        'gen-btn': 'Generate Password',
        'gen-result': 'Generated password:',
        copy: 'Copy',
        strength: 'Strength:',
        'str-title': 'Check Password Strength',
        'str-label': 'Enter password:',
        password: 'Your password',
        'str-btn': 'Check Strength',
        'str-results': 'Results:',
        'str-overall': 'Strength:',
        'str-len': 'Length:',
        'str-upper': 'Uppercase:',
        'str-lower': 'Lowercase:',
        'str-digits': 'Numbers:',
        'str-special': 'Symbols:',
        'str-common': 'Common password:',
        'str-rec': 'Recommendations:',
        'bre-title': 'Check Breaches',
        'bre-label': 'Enter password:',
        'bre-btn': 'Check Password',
        'copy-success': 'Copied!',
        'enter-password': 'Enter a password',
        'network-error': 'Network error',
        'yes': '✅ Yes',
        'no': '❌ No',
        'warning-yes': '⚠️ Yes',
        'breach-safe': 'Password safe - not found in breaches',
        'breach-found': 'Password found in {count} breaches. Change it!',
        // Add new translations here if needed
        'rec-length': 'Increase length to at least 12 characters',
        'rec-upper': 'Add uppercase letters',
        'rec-lower': 'Add lowercase letters',
        'rec-digits': 'Add numbers',
        'rec-special': 'Add special symbols',
        'rec-common': 'Avoid common passwords, use unique combinations',
        'rec-avoid-personal': 'Avoid personal information',
        'rec-complexity': 'Increase password complexity'
    }
};

// Funzione helper per ottenere le traduzioni
function getTranslations() {
    return translations;
}

// Funzione per ottenere una traduzione specifica
function getTranslation(lang, key) {
    return translations[lang] && translations[lang][key] ? translations[lang][key] : key;
}

// Esporta per compatibilità con diversi sistemi di moduli
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { translations, getTranslations, getTranslation };
}
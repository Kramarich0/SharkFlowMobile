# Аудит безопасности: SecureCrypto.kt

## Strengths
- Правильное использование Android Keystore для управления ключами.
- Корректная реализация AES-GCM с уникальными IV для каждой операции.

## Issues & Fixes
- **ArrayIndexOutOfBoundsException:** Добавлена проверка размера массива в методе `decrypt`.
- **Base64 Line Breaks:** Использование `Base64.NO_WRAP` исключает появление лишних символов переноса строки.
- **Encoding Issues:** Явно указан `Charsets.UTF_8` для предотвращения ошибок при кодировании.

---
# Документация: SecureCrypto.kt

Singleton-объект для безопасного шифрования AES-GCM через Android Keystore.
- `encrypt(data: String)`: Шифрует строку, возвращая Base64-строку (IV + шифртекст).
- `decrypt(encryptedData: String)`: Дешифрует данные, проверяя их целостность.
# bcrypt

bcrypt for hash and verify password

## How to use

```bash
npm install --save @liuhlightning/bcrypt
# or
yarn add @liuhlightning/bcrypt
```

```typescript
import { hash, verify } from "@liuhlightning/bcrypt";

const passwordHash = hash("your password");
// store the password hash

const isThatYou = verify("input password", passwordHash);
```

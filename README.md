# Zalter Identity - Browser SDK

A browser side software developer kit meant to be used for the Zalter Identity Service offered by Zalter.

## Installation
```bash
npm install @zalter/identity-js
```

## Usage

```javascript
import { Auth } from '@zalter/identity-js';

const auth = new Auth({
  projectId: '<projectId>' // replace with your own projectId
});

await auth.signInWithCode('start', {
  email: 'example@example.com' // Email of the user you want to authenticate. 
});

await auth.signInWithCode('finalize', {
  code: '<code>' // Email of the user you want to authenticate. 
});

const isAuthenticated = await auth.isAuthenticated();

const user = await auth.getCurrentUser();

// user.signMessage();
```

## Documentation

[Zalter Docs Website](https://docs.zalter.com)

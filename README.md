### How to setup and run

#### Generate a private / public pair of keys with

```
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
```

#### Run the server

```
npm run start
```

#### Open your web browser in http://localhost:3000/

### Key Points of the Cookie Flow

- **Cookie Storage**: When a user logs in, a token is generated that includes the user's identification. This token is stored in a secure cookie in the user's browser.

- **Secure Cookies**: The cookie is configured to be `Secure`, meaning it will only be transmitted over HTTPS connections. This protects the cookie from being intercepted during transmission.

- **HttpOnly Attribute**: The cookie is set with the `HttpOnly` attribute, which prevents client-side scripts from accessing it. This significantly reduces the risk of attacks like Cross-Site Scripting (XSS).

- **Token Expiration**: The token stored in the cookie has a defined expiration time. After this time elapses, the token is no longer valid.

- **Token Validation**: When the user attempts to access a protected resource, the server checks the validity of the token stored in the cookie. If the token is valid, the user is granted access; if not, an error message is returned.

- **Refreshing the Token**: There is a mechanism in place to refresh the token when it is close to expiring. This allows the user to maintain their session without needing to log in again, ensuring a smoother user experience.

### Summary

This cookie flow implements a secure authentication mechanism that uses cookies to store user identification tokens. It ensures secure transmission and protection from unauthorized access, while also providing a way to refresh tokens for continuous access.

### Additional Context

For this Proof of Concept (PoC), we are accessing a "resource." However, in a real production environment, we would be validating whether this is a trusted device.

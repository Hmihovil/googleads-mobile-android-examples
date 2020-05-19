**To start with Java :**

- `cd RewardedSSVExample`
- `./gradlew bootRun`

**To start with Docker:**

- `docker-compose up --build`

**To test a different signature and message:**

- Send `GET` request to `localhost:8080/verify?<dataToVerify>&signature=<signature>&key_id=<key_id>`

- Valid Request Example:
```
curl -X GET 'http://localhost:8080/verify?ad_network=54...55&ad_unit=12345678&reward_amount=10&reward_item=coins
&timestamp=150777823&transaction_id=12...DEF&user_id=1234567&signature=ME...Z1c&key_id=1268887'
```
- Success Response Example:
```
{
  "sig": "ME...Z1c",
  "payload": "ad_network=54...55&ad_unit=12345678&reward_amount=10&reward_item=coins &timestamp=150777823&transaction_id=12...DEF&user_id=1234567",
  "key_id": "1268887",
  "verified": "true"
}
```

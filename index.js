import express from 'express';
import nonce from 'nonce';
import dotenv from 'dotenv';
import cookie from 'cookie'
import querystring from 'querystring'
import crypto from 'crypto'
import axios from 'axios'
const scopes = "write_products";

dotenv.config();
const apiKey = process.env.SHOPIFY_API_KEY;
const forwardingAddress = process.env.SHOPIFY_API_URL;
const API_VERSION = '2023-04' 
const DOMAIN = process.env.DOMAIN
const app = express()

const redirectURL = () => `${forwardingAddress}/shopify/callback`
const installUrl = (shop, state, redirectURL) => `https://${shop}/admin/oauth/authorize?client_id=${apiKey}&scope=${scopes}&state=${state}&redirect_uri=${redirectURL}`
const accessTokenRequestUrl = (shop) => `https://${shop}/admin/oauth/access_token`;
const generateEncryptedHash = (params) => crypto.createHmac('sha256', process.env.SHOPIFY_API_SECRET).update(params).digest('hex');
const shopDataRequestUrl = (shop) => `https://${shop}/admin/shop.json`;
/////////////////// Shopify Service ////////////////////

const fetchAccessToken = async (shop, data) => await axios(accessTokenRequestUrl(shop), {
    method: 'POST',
    data
});

const fetchShopData = async (shop, accessToken) => await axios(shopDataRequestUrl(shop), {
    method: 'GET',
    headers: {
      'X-Shopify-Access-Token': accessToken
    }
});

const fetchAccessScope = async () => {
    const data = await axios.get(`https://${DOMAIN}/admin/oauth/access_scopes.json`, 
    {
        headers: {
            "X-Shopify-Access-Token": process.env.SHOPIFY_ACCESS_TOKEN
        }
    })
    return data;
}

const storefrontAccessToken = async (shop) => {
    const data = await axios.get(`https://${shop}/admin/api/${API_VERSION}/storefront_access_tokens.json`,
    {
        headers: {
            "X-Shopify-Access-Token": process.env.SHOPIFY_ACCESS_TOKEN
        }
    })
    return data
}

const fetchProduct = async (shop) => {
    const data = await axios.get(`https://${shop}/admin/api/${API_VERSION}/products.json`,
    {
        headers: {
            "X-Shopify-Access-Token": process.env.SHOPIFY_ACCESS_TOKEN
        }
    })

    return data
}

const fetchOrder = async (shop) => {
    const data = await axios.get(`https://${shop}/admin/api/${API_VERSION}/orders.json`,
    {
        headers: {
            "X-Shopify-Access-Token": process.env.SHOPIFY_ACCESS_TOKEN
        }
    })
    return data
}

///////////// Route Handlers /////////////

app.get('/', async (req, res) => {
    try {
        const response = await fetchAccessScope();
        res.send(response.data)
    } catch (err) {
        res.send(err.message)
    }
})

app.get('/shopify', (req, res) => {
    const shop = req.query.shop;
  
    if (!shop) { return res.status(400).send('no shop')}
  
    const state = nonce()();
  
    const installShopUrl = installUrl(shop, state, redirectURL())
  
    res.cookie('state', state) // should be encrypted in production
    res.redirect(installShopUrl);
});
  
app.get('/shopify/callback', async (req, res) => {
  const { shop, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;
  
    if (state !== stateCookie) { return res.status(403).send('Cannot be verified')}
    const { hmac, ...params } = req.query
    const queryParams = querystring.stringify(params)
    const hash = generateEncryptedHash(queryParams)
  
    if (hash !== hmac) { return res.status(400).send('HMAC validation failed')}
  
    try {
      const data = {
        client_id: apiKey,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code
      };
      const tokenResponse = await fetchAccessToken(shop, data)
      const { access_token } = tokenResponse.data
  
      const shopData = await fetchShopData(shop, access_token)
      res.send(shopData.data.shop)
  
    } catch(err) {
      res.status(500).send('something went wrong')
    }
});

app.get('/storefront-access', async (req, res) => {
    try {
        const response = await storefrontAccessToken(DOMAIN);
        if (response) {res.send(response.data)}
    } catch(err) {
        res.send(err.message)
    }
});

app.get('/products', async (req, res) => {
    try {
        const response = await fetchProduct(DOMAIN);
        if (response) {res.send(response.data.products)}
    } catch(err) {
        res.send(err.message)
    }
});

app.get('/orders', async (req, res) => {
    try {
        const response = await fetchOrder(DOMAIN);
        if (response) {res.send(response.data.orders)}
    } catch(err) {
        res.send(err.message)
    }
});
  
///////////// Start the Server /////////////

app.listen(3434)
const expect = require('chai').expect;
const authMiddleware = require('../APIs/middleware/is-auth');
const jwt = require('../APIs/node_modules/jsonwebtoken');
const sinon = require('sinon');

describe('Auth Middleware', function() {
  it('Should throw an error if no authorization header is present', function() {
    const req = {
      get: function(headerName) {
        return null;
      }
    };
    expect(authMiddleware.bind(this, req, {}, () => {})).to.throw(
      'Not Authorized'
    );
  });

  it('Should throw an error if authorization header is only one string', function() {
    const req = {
      get: function(headerName) {
        return 'xyz';
      }
    };
    expect(authMiddleware.bind(this, req, {}, () => {})).to.throw();
  });

  it('Should throw an error if the token cannot be verified', function() {
    const req = {
      get: function(headerName) {
        return 'Bearer xyz';
      }
    };
    expect(authMiddleware.bind(this, req, {}, () => {})).to.throw();
  });

  it('Should yield a userId after decoding the token', function() {
    const req = {
      get: function(headerName) {
        return 'Bearer bvre98hvrjponuvbrw';
      }
    };
    sinon.stub(jwt, 'verify');
    jwt.verify.returns({ userId: 'abc' });

    authMiddleware(req, {}, () => {});
    expect(req).to.have.property('userId');
    expect(req).to.have.property('userId', 'abc');

    jwt.verify.restore();
  });
});

import {Component, provide} from '@angular/core';
import {ROUTER_DIRECTIVES, RouteConfig, ROUTER_PRIMARY_COMPONENT} from '@angular/router-deprecated';
import {Login} from './login/login';
import {Signup} from './signup/signup';
import {Main} from './main/main';
import {NG2_UI_AUTH_PROVIDERS} from 'ng2-ui-auth';
import {IOauth2Options} from 'ng2-ui-auth/declerations/config';

// from http://127.0.0.1:9999/clientids.js index.html
declare var ClientIds: Dict<string>;

const MOCK_PROVIDER: IOauth2Options = {
  clientId: ClientIds['mock'],
  name: 'mock',
  url: '/auth/mock',
  authorizationEndpoint: 'http://127.0.0.1:14000/authorize',
  redirectUri: window.location.origin,
  requiredUrlParams: ['state'],
  state: () => Math.random().toString(36).slice(2),
  type: '2.0'
}

// add facebook support
const FACEBOOK_PROVIDER: IOauth2Options = {
  clientId: ClientIds['facebook']
}

@Component({
  selector: 'app',
  providers: [
    provide(ROUTER_PRIMARY_COMPONENT, { useFactory: () => App }),
    NG2_UI_AUTH_PROVIDERS({
      baseUrl: 'http://127.0.0.1:9999',
      providers: { mock: MOCK_PROVIDER, facebook: FACEBOOK_PROVIDER }
    }),
  ],
  template: '<router-outlet></router-outlet>',
  directives: [Login, ROUTER_DIRECTIVES]
})
@RouteConfig([
  { path: '/main/...', name: 'Main', component: Main },
  { path: '/login', name: 'Login', component: Login, useAsDefault: true },
  { path: '/signup', name: 'Signup', component: Signup },
])
export class App { }

import {Component, provide} from '@angular/core';
import {ROUTER_DIRECTIVES, RouteConfig, ROUTER_PRIMARY_COMPONENT} from '@angular/router-deprecated';
import {Login} from './login/login';
import {Signup} from './signup/signup';
import {Main} from './main/main';
import {NG2_UI_AUTH_PROVIDERS} from 'ng2-ui-auth';
import {IOauth2Options} from 'ng2-ui-auth/declerations/config';

const MOCK_PROVIDER: IOauth2Options = {
  clientId: '1234',
  name: 'mock',
  url: 'http://127.0.0.1:9999/auth/mock',
  authorizationEndpoint: 'http://127.0.0.1:14000/authorize',
  redirectUri: window.location.origin,
  requiredUrlParams: ['state'],
  state: () => Math.random().toString(36).slice(2),
  type: '2.0'
}

@Component({
  selector: 'app',
  providers: [
    provide(ROUTER_PRIMARY_COMPONENT, { useFactory: () => App }),
    NG2_UI_AUTH_PROVIDERS({ providers: { mock: MOCK_PROVIDER } }),
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

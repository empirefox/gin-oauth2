import {Component} from '@angular/core';
import {RouteConfig, ROUTER_DIRECTIVES, Router} from '@angular/router-deprecated';
import {Auth, JwtHttp, Config} from 'ng2-ui-auth';
import {Observable} from 'rxjs/Observable';
import {Http} from '@angular/http';

@Component({
  selector: 'app-overview',
  template: `<p>{{helloWorld | async}}</p><p>{{helloWorldError}}</p><button type="button" (click)="signout()">signout</button>`,
  directives: [ROUTER_DIRECTIVES]
})
class Overview {
  helloWorld: Observable<string>;
  helloWorldError: string = 'sdf';

  constructor(
    private auth: Auth,
    private router: Router,
    private jwtHttp: JwtHttp,
    private http: Http) {
    this.helloWorld = jwtHttp.get('http://127.0.0.1:9999/api/helloWorld').map((response) => response.text());
    http.get('http://127.0.0.1:9999/api/helloWorld')
      .subscribe(
      (response) => {
        this.helloWorldError = response.text();
      },
      (response) => {
        this.helloWorldError = response.text();
      });
  }

  signout() {
    this.auth.logout().subscribe(() => {
      this.router.navigate(['/Login']);
    })
  }
}

@Component({
  selector: 'app-main',
  template: '<router-outlet></router-outlet>',
  directives: [ROUTER_DIRECTIVES]
})
@RouteConfig([
  { path: 'overview', name: 'Overview', component: Overview, useAsDefault: true },
])
export class Main {
}

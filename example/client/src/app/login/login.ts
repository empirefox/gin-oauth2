import {Component, AfterContentInit, ElementRef, Renderer, OnInit} from '@angular/core';
import {FormBuilder, ControlGroup, Control, Validators} from '@angular/common';
import {Router, ROUTER_DIRECTIVES} from '@angular/router-deprecated';
import {Auth} from 'ng2-ui-auth';
import {NgMessages} from '../formComponents/ngMessages';
import {EmailValidator} from '../formComponents/customValidators';

@Component({
  selector: 'app-login',
  template: require('./login.html'),
  directives: [NgMessages, ROUTER_DIRECTIVES, EmailValidator],
})
export class Login implements AfterContentInit, OnInit {
  user = { email: '', password: '' };
  form: ControlGroup;

  constructor(
    private auth: Auth,
    private router: Router,
    private element: ElementRef,
    private renderer: Renderer,
    private fb: FormBuilder) { }

  ngOnInit() {
    this.form = this.fb.group({
      email: new Control('', Validators.compose([Validators.required, EmailValidator.validate])),
      password: new Control('', Validators.required)
    });
  }

  ngAfterContentInit() {
    this.renderer.setElementClass(this.element.nativeElement, 'app', true);
    if (this.auth.isAuthenticated()) {
      this.goToMain();
    }
  }

  login() {
    this.auth.login(this.user).subscribe(() => this.goToMain());
  }

  authenticate(provider: string) {
    this.auth.authenticate(provider).subscribe(() => this.goToMain());
  }

  goToMain() {
    this.router.navigate(['Main']);
  }

}

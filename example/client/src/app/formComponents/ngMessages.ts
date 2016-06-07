import {Component, Input, OnChanges} from '@angular/core';

@Component({
  selector: 'ng-messages',
  template: require('./ngMessages.html')
})
export class NgMessages implements OnChanges {
  error = '';
  @Input() errors: Object;

  ngOnChanges(changes: any): any { //changes looks like this changes.theInputVariable.currentValue/previousValue
    if (changes.errors.currentValue) {
      for (let errorProp of Object.keys(changes.errors.currentValue)) {
        if (changes.errors.currentValue[errorProp]) {
          this.error = errorProp;
          break;
        }
      }
    } else {
      this.error = null;
    }
  }
}

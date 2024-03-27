<template>
  <input 
    v-bind:value="value"
    v-on:keydown="discardIllegalEntries($event)"
    v-on:input="$emit('input', updateCurrencyStr($event))"
    ref="input"
  />
</template>
<script>
  import { ref } from 'vue'
  export default {
    props: ['value'],
    setup() {
      const input = ref(null)
      return {
        input
      }
    },
    methods: {
      discardIllegalEntries(evt) {
        if (this.isIllegalEntry(evt)) {
          evt.preventDefault()
        }
      },

      isIllegalEntry(evt) {
        if (evt.altKey || evt.ctrlKey || evt.metaKey) return false  // we don't care what's pressed if alt, ctrl or command are also held down
        const keyCode = evt.keyCode
        const is58To90 = keyCode > 57 && keyCode < 91               // 58-90 are punctuation, math symbols and letters
        const is106To111 = keyCode > 105 && keyCode < 112           // 106-111 are math operation symbols
        const is160 = keyCode === 160                               // 160 is ^ symbol
        const is163To165 = keyCode > 162 && keyCode < 166           // 163-165 are currency symbols
        const is169To173 = keyCode > 168 && keyCode < 174           // 169-173 are copyright, trademark, registered, section, dash
        const is186To223 = keyCode > 185 && keyCode < 224           // 186-223 are punctuation, symbols, math symbols
        const is226 = keyCode === 226                               // 226 is < symbol
        const isShiftPlusNumber = evt.shiftKey && this.isNumber(keyCode)
        const illegalEntries = [is58To90, is106To111, is160, is163To165, is169To173, is186To223, is226, isShiftPlusNumber]
        const isEntryIllegal = illegalEntries.some(Boolean)         // are any vals in array truthy, https://www.30secondsofcode.org/js/s/check-array-values-are-truthy/#check-if-all-values-in-an-array-are-truthy
        return isEntryIllegal
      },

      isNumber(keyCode) {
        return keyCode > 47 && keyCode < 58 || keyCode > 95 && keyCode < 106
      },

      // @param rawCurrencyInt: 6327397 would represent $63,273.97
      // @return allButLastTwoWithCommas: '63,273'
      dollarsStrFromRawCurrencyInt(rawCurrencyInt) {
        const allButLastTwo = rawCurrencyInt.toString().slice(0, -2)
        const addCommasRegex = /\B(?=(\d{3})+(?!\d))/g
        const allButLastTwoWithCommas = allButLastTwo.replace(addCommasRegex, ',')
        return allButLastTwoWithCommas
      },

      // @param rawCurrencyInt: 6327397 would represent $63,273.97
      // @return lastTwo: '97'
      centsStrFromRawCurrencyInt(rawCurrencyInt) {
        const lastTwo = rawCurrencyInt.toString().slice(-2)
        return lastTwo
      },

      currencyStrFromDollarsAndCents(dollars, cents) {
        return `$${dollars}.${cents}`
      },

      currencyStrFromRawCurrencyInt(rawCurrencyInt) {
        const dollars = this.dollarsStrFromRawCurrencyInt(rawCurrencyInt)
        const cents = this.centsStrFromRawCurrencyInt(rawCurrencyInt)
        return this.currencyStrFromDollarsAndCents(dollars, cents)
      },

      // @param currencyStr: '$63,273.97'
      // @return rawCurrencyInt: 6327397
      rawCurrencyIntFromCurrencyStr(currencyStr) {
        if (currencyStr === '') 
          return ''
        else
          return parseInt(currencyStr.replace(/[^\d]/g, ''))
      },

      // @param changedCurrencyStr: '$63,273.397'
      // @return fixedCurrencyStr: '$632,733.97'
      updateCurrencyStr(evt) {
        const changedCurrencyStr = evt.target.value
        const strLenAtStart = changedCurrencyStr.length
        const cursorPosition = evt.target.selectionStart
        const rawCurrencyInt = this.rawCurrencyIntFromCurrencyStr(changedCurrencyStr)
        let correctedCurrencyStr = ''
        switch (rawCurrencyInt.toString().length) {
          case 0:
            break
          case 1:
            correctedCurrencyStr = `$0.0${rawCurrencyInt}`;
            break
          case 2:
            correctedCurrencyStr = `$0.${rawCurrencyInt}`;
            break
          case 3:
          case 4:
            correctedCurrencyStr = this.currencyStrFromRawCurrencyInt(rawCurrencyInt)
            break
          default:
            correctedCurrencyStr = this.currencyStrFromRawCurrencyInt(rawCurrencyInt)
        }
        setTimeout(() => {
          const strLenAtEnd = correctedCurrencyStr.length
          const cursorPositionOffset = strLenAtEnd - strLenAtStart
          const newCursorPosition = cursorPosition + cursorPositionOffset
          this.$refs.input.setSelectionRange(newCursorPosition, newCursorPosition);
        });
        return correctedCurrencyStr
      }
    }
  }
</script>
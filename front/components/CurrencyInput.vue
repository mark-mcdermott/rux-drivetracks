<template>
  <input v-model="val" @keydown="discardIllegalKeys" @keyup="processKeyUp" />
</template>
<script>
  export default {
    data() {
      return {
        val: ''
      }
    },

    methods: {

      processKeyUp() {
        this.val = this.correctChangedCurrencyStr(this.val)
      },

      discardIllegalKeys(evt) {
        if (!this.isNumKey(evt) && !this.isArrowBackspaceOrDeleteKey(evt)) {
          evt.preventDefault()
        }
      },

      isArrowBackspaceOrDeleteKey(evt) {
        const keyCode = evt.keyCode
        const isDelete = keyCode === 8
        const isBackspace = keyCode === 46
        const isArrow = keyCode > 36 && keyCode < 41
        return (isDelete || isBackspace || isArrow) ? true : false
      },

      isNumKey(evt) {
        return evt.key.match(/[0-9]/) ? true : false
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
        return parseInt(currencyStr.replace(/[^\d]/g, ''))
      },

      // @param changedCurrencyStr: '$63,273.397'
      // @return fixedCurrencyStr: '$632,733.97'
      correctChangedCurrencyStr(changedCurrencyStr) {
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
        return correctedCurrencyStr
      }

    }
  }
</script>
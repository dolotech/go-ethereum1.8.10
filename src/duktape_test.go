package main

import (
	"testing"
	"gopkg.in/olebedev/go-duktape.v3"
)

func Test(t *testing.T) {
	ctx := duktape.New()

	// Let's inject `setTimeout`, `setInterval`, `clearTimeout`,
	// `clearInterval` into global scope.
	ctx.PushTimers()

	ch := make(chan string)
	ctx.PushGlobalGoFunction("second", func(_ *duktape.Context) int {
		ch <- "second step"
		return 0
	})
	ctx.PevalString(`
    setTimeout(second, 0);
    print('first step');
  `)
	t.Log(<-ch)
}

func Test_1(t *testing.T) {
	ctx := duktape.New()

	ctx.PushGlobalGoFunction("log", func(c *duktape.Context) int {
		t.Log(c.SafeToString(-1))
		return 0
	})

	ctx.PevalString(`log('Go lang Go!')`)
	ctx.PevalString(`log("hello world!")`)
}
func Test_2(t *testing.T) {
	ctx := duktape.New()
	ctx.PevalString(`2 + 3`)
	result := ctx.GetNumber(-1)
	ctx.Pop()
	t.Log("result is:", result)
	// To prevent memory leaks, don't forget to clean up after
	// yourself when you're done using a context.
	ctx.DestroyHeap()
}

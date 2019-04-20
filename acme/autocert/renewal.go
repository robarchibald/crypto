// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"context"
	"crypto"
	"fmt"
	"sync"
	"time"
)

// renewJitter is the maximum deviation from Manager.RenewBefore.
const renewJitter = time.Hour

// domainRenewal tracks the state used by the periodic timers
// renewing a single domain's cert.
type domainRenewal struct {
	m   *Manager
	ck  certKey
	key crypto.Signer

	timerMu sync.Mutex
	timer   *time.Timer
}

// start starts a cert renewal timer at the time
// defined by the certificate expiration time exp.
//
// If the timer is already started, calling start is a noop.
func (dr *domainRenewal) start(exp time.Time) {
	fmt.Println("domainRenewal start called")
	dr.timerMu.Lock()
	defer dr.timerMu.Unlock()
	if dr.timer != nil {
		return
	}
	dr.timer = time.AfterFunc(dr.next(exp), dr.renew)
}

// stop stops the cert renewal timer.
// If the timer is already stopped, calling stop is a noop.
func (dr *domainRenewal) stop() {
	fmt.Println("domainRenewal stop called")
	dr.timerMu.Lock()
	defer dr.timerMu.Unlock()
	if dr.timer == nil {
		return
	}
	dr.timer.Stop()
	dr.timer = nil
}

// renew is called periodically by a timer.
// The first renew call is kicked off by dr.start.
func (dr *domainRenewal) renew() {
	fmt.Println("domainRenewal renew called")
	dr.timerMu.Lock()
	defer dr.timerMu.Unlock()
	if dr.timer == nil {
		return
	}

	fmt.Println("domainRenewal renew getting context")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// TODO: rotate dr.key at some point?
	fmt.Println("domainRenewal renew calling do")
	next, err := dr.do(ctx)
	if err != nil {
		next = renewJitter / 2
		next += time.Duration(pseudoRand.int63n(int64(next)))
	}
	dr.timer = time.AfterFunc(next, dr.renew)
	testDidRenewLoop(next, err)
}

// updateState locks and replaces the relevant Manager.state item with the given
// state. It additionally updates dr.key with the given state's key.
func (dr *domainRenewal) updateState(state *certState) {
	fmt.Println("domainRenewal updateState called")
	dr.m.stateMu.Lock()
	defer dr.m.stateMu.Unlock()
	dr.key = state.key
	dr.m.state[dr.ck] = state
}

// do is similar to Manager.createCert but it doesn't lock a Manager.state item.
// Instead, it requests a new certificate independently and, upon success,
// replaces dr.m.state item with a new one and updates cache for the given domain.
//
// It may lock and update the Manager.state if the expiration date of the currently
// cached cert is far enough in the future.
//
// The returned value is a time interval after which the renewal should occur again.
func (dr *domainRenewal) do(ctx context.Context) (time.Duration, error) {
	fmt.Println("domainRenewal do called")
	// a race is likely unavoidable in a distributed environment
	// but we try nonetheless
	if tlscert, err := dr.m.cacheGet(ctx, dr.ck); err == nil {
		fmt.Println("domainRenewal do inside cacheGet")
		next := dr.next(tlscert.Leaf.NotAfter)
		if next > dr.m.renewBefore()+renewJitter {
			signer, ok := tlscert.PrivateKey.(crypto.Signer)
			if ok {
				fmt.Println("domainRenewal do inside ok")
				state := &certState{
					key:  signer,
					cert: tlscert.Certificate,
					leaf: tlscert.Leaf,
				}
				fmt.Println("domainRenewal do calling updateState")
				dr.updateState(state)
				return next, nil
			}
		}
	}

	fmt.Println("domainRenewal do calling authorizedCert")
	der, leaf, err := dr.m.authorizedCert(ctx, dr.key, dr.ck)
	if err != nil {
		return 0, err
	}
	state := &certState{
		key:  dr.key,
		cert: der,
		leaf: leaf,
	}
	fmt.Println("domainRenewal do calling tlscert")
	tlscert, err := state.tlscert()
	if err != nil {
		return 0, err
	}
	fmt.Println("domainRenewal do calling cachePut")
	if err := dr.m.cachePut(ctx, dr.ck, tlscert); err != nil {
		return 0, err
	}
	fmt.Println("domainRenewal do calling updateState")
	dr.updateState(state)
	return dr.next(leaf.NotAfter), nil
}

func (dr *domainRenewal) next(expiry time.Time) time.Duration {
	fmt.Println("domainRenewal next called")
	d := expiry.Sub(dr.m.now()) - dr.m.renewBefore()
	// add a bit of randomness to renew deadline
	n := pseudoRand.int63n(int64(renewJitter))
	d -= time.Duration(n)
	if d < 0 {
		return 0
	}
	return d
}

var testDidRenewLoop = func(next time.Duration, err error) {}

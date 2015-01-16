package pkmacaroon_test
import (
	"fmt"
	"testing"

	gc "gopkg.in/check.v1"
	"github.com/rogpeppe/pkmacaroon"
)

func TestPackage(t *testing.T) {
	gc.TestingT(t)
}

type macaroonSuite struct{}

var _ = gc.Suite(&macaroonSuite{})

func (*macaroonSuite) TestNoCaveats(c *gc.C) {
	keyPair, err := pkmacaroon.NewKeyPair()
	c.Assert(err, gc.IsNil)

	m, err := pkmacaroon.New(&keyPair.Private, "an id")
	c.Assert(err, gc.IsNil)

	m.Finalize()

	err = m.Verify(&keyPair.Public)
	c.Assert(err, gc.IsNil)
}

func (*macaroonSuite) TestFirstPartyCaveat(c *gc.C) {
	keyPair, err := pkmacaroon.NewKeyPair()
	c.Assert(err, gc.IsNil)

	m, err := pkmacaroon.New(&keyPair.Private, "an id")
	c.Assert(err, gc.IsNil)

	err = m.AddCaveat("some caveat")
	c.Assert(err, gc.IsNil)

	m.Finalize()

	err = m.Verify(&keyPair.Public)
	c.Assert(err, gc.IsNil)

	keyPair.Public[0]++
	err = m.Verify(&keyPair.Public)
	c.Assert(err, gc.ErrorMatches, "signature verification error")
}

func (*macaroonSuite) TestSeveralCaveats(c *gc.C) {
	keyPair, err := pkmacaroon.NewKeyPair()
	c.Assert(err, gc.IsNil)

	m, err := pkmacaroon.New(&keyPair.Private, "an id")
	c.Assert(err, gc.IsNil)

	for i := 0; i < 10; i++ {
		err = m.AddCaveat(fmt.Sprintf("some caveat %d", i))
		c.Assert(err, gc.IsNil)
	}

	m.Finalize()

	err = m.Verify(&keyPair.Public)
	c.Assert(err, gc.IsNil)
}

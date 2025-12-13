// Copyright 2019-2024 go-tcap authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/*
Package tcap provides simple and painless handling of TCAP(Transaction Capabilities Application Part) in SS7/SIGTRAN protocol stack.

Though TCAP is ASN.1-based protocol, this implementation does not use any ASN.1 parser.
That makes this implementation flexible enough to create arbitrary payload with any combinations, which is useful for testing.
*/
package tcap

import (
	"encoding/binary"
	"fmt"
)

// TCAP represents a General Structure of TCAP Information Elements.
type TCAP struct {
	Transaction *Transaction
	Dialogue    *Dialogue
	Components  *Components
}

// NewBeginInvoke creates a new TCAP of type Transaction=Begin, Component=Invoke.
func NewBeginInvoke(otid uint32, invID int, opCode uint8, payload []byte) *TCAP {
	t := &TCAP{
		Transaction: NewBegin(otid, []byte{}),
		Components:  NewComponents(NewInvoke(invID, -1, opCode, true, payload)),
	}
	t.SetLength()

	return t
}

// NewBeginInvokeWithDialogue creates a new TCAP of type Transaction=Begin, Component=Invoke with Dialogue Portion.
func NewBeginInvokeWithDialogue(otid uint32, dlgType, ctx, ctxver uint8, invID int, opCode uint8, payload []byte) *TCAP {
	t := NewBeginInvoke(otid, invID, opCode, payload)
	t.Dialogue = NewDialogue(dlgType, 1, NewAARQ(1, ctx, ctxver), []byte{})
	t.SetLength()

	return t
}

// NewContinueInvoke creates a new TCAP of type Transaction=Continue, Component=Invoke.
func NewContinueInvoke(otid, dtid uint32, invID int, opCode uint8, payload []byte) *TCAP {
	t := &TCAP{
		Transaction: NewContinue(otid, dtid, []byte{}),
		Components:  NewComponents(NewInvoke(invID, -1, opCode, true, payload)),
	}
	t.SetLength()

	return t
}

// NewEndReturnResult creates a new TCAP of type Transaction=End, Component=ReturnResult.
func NewEndReturnResult(dtid uint32, invID int, opCode uint8, isLast bool, payload []byte) *TCAP {
	t := &TCAP{
		Transaction: NewEnd(dtid, []byte{}), // Use the actual dtid parameter
		Components:  NewComponents(NewReturnResult(invID, opCode, true, isLast, payload)),
	}
	t.SetLength()
	return t
}

// NewEndReturnResultWithDialogue creates a new TCAP of type Transaction=End, Component=ReturnResult with Dialogue Portion.
func NewEndReturnResultWithDialogue(dtid uint32, dlgType, ctx, ctxver uint8, invID int, opCode uint8, isLast bool, payload []byte) *TCAP {
	t := NewEndReturnResult(dtid, invID, opCode, isLast, payload)
	t.Dialogue = NewDialogue(dlgType, 1, NewAARE(ctx, ctxver, Accepted, DialogueServiceUser, Null), []byte{})
	t.SetLength()

	return t
}

// NewEndReturnError creates a new TCAP of type Transaction=End, Component=ReturnError.
func NewEndReturnError(dtid uint32, invID int, errCode uint8, isLocal bool, payload []byte) *TCAP {
	t := &TCAP{
		Transaction: NewEnd(dtid, []byte{}), // Use the actual dtid parameter
		Components:  NewComponents(NewReturnError(uint8(invID), errCode, isLocal, payload)),
	}
	t.SetLength()
	return t
}

// NewEndReturnErrorWithDialogue creates a new TCAP of type Transaction=End, Component=ReturnError with Dialogue Portion.
func NewEndReturnErrorWithDialogue(dtid uint32, dlgType, ctx, ctxver uint8, invID int, errCode uint8, isLocal bool, payload []byte) *TCAP {
	t := NewEndReturnError(dtid, invID, errCode, isLocal, payload)
	t.Dialogue = NewDialogue(dlgType, 1, NewAARE(ctx, ctxver, Accepted, DialogueServiceUser, Null), []byte{})
	t.SetLength()

	return t
}

// MarshalBinary returns the byte sequence generated from a TCAP instance.
func (t *TCAP) MarshalBinary() ([]byte, error) {
	b := make([]byte, t.MarshalLen())
	if err := t.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
func (t *TCAP) MarshalTo(b []byte) error {
	var offset = 0
	if portion := t.Transaction; portion != nil {
		if err := portion.MarshalTo(b[offset : offset+portion.MarshalLen()]); err != nil {
			return err
		}
		offset += portion.MarshalLen()
	}

	if portion := t.Dialogue; portion != nil {
		if err := portion.MarshalTo(b[offset : offset+portion.MarshalLen()]); err != nil {
			return err
		}
		offset += portion.MarshalLen()
	}

	if portion := t.Components; portion != nil {
		if err := portion.MarshalTo(b[offset : offset+portion.MarshalLen()]); err != nil {
			return err
		}
	}

	return nil
}

// Parse parses given byte sequence as a TCAP.
func Parse(b []byte) (*TCAP, error) {
	t := &TCAP{}
	if _, err := t.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	return t, nil
}

// UnmarshalBinary sets the values retrieved from byte sequence in a TCAP.
/*func (t *TCAP) UnmarshalBinary(b []byte) error {
	var err error
	var offset = 0

	t.Transaction, err = ParseTransaction(b[offset:])
	if err != nil {
		fmt.Printf(" 1 tcap err returning from here")
		return err
	}
	if len(t.Transaction.Payload) == 0 {
		return nil
	}

	switch t.Transaction.Payload[0] {
	case 0x6b:
		t.Dialogue, err = ParseDialogue(t.Transaction.Payload)
		if err != nil {
			fmt.Printf(" tcap 2 err returning from here")
			return err
		}
		if len(t.Dialogue.Payload) == 0 {
			return nil
		}

		t.Components, err = ParseComponents(t.Dialogue.Payload)
		if err != nil {
			fmt.Printf(" 3  tcap err returning from here")
			return err
		}
	case 0x6c:
		t.Components, err = ParseComponents(t.Transaction.Payload)
		if err != nil {
			fmt.Printf(" 4 tcap err returning from here")
			return err
		}
	}

	return nil
}*/
/*func (t *TCAP) UnmarshalBinary(b []byte) error {
	var err error
	var offset = 0

	t.Transaction, err = ParseTransaction(b[offset:])
	if err != nil {
		fmt.Printf(" 1 tcap err returning from here")
		return err
	}
	if len(t.Transaction.Payload) == 0 {
		return nil
	}

	// Parse the payload sequentially
	payload := t.Transaction.Payload
	payloadOffset := 0

	// Check for Component Portion first (0x6b)
	if payload[payloadOffset] == 0x6b {
		componentLength := int(payload[payloadOffset+1])

		// Extract component data
		componentData := payload[payloadOffset : payloadOffset+2+componentLength]
		t.Components, err = ParseComponents(componentData)
		if err != nil {
			fmt.Printf(" 3 tcap err returning from here")
			return err
		}
		payloadOffset += 2 + componentLength
	}

	// Check for Dialogue Portion (0xa0) after components
	if payloadOffset < len(payload) && payload[payloadOffset] == 0xa0 {
		dialogueLength := int(payload[payloadOffset+1])

		// Extract dialogue data
		dialogueData := payload[payloadOffset : payloadOffset+2+dialogueLength]
		t.Dialogue, err = ParseDialogue(dialogueData)
		if err != nil {
			fmt.Printf(" 2 tcap err returning from here")
			return err
		}
		payloadOffset += 2 + dialogueLength
	}

	// Check for User Information (0x6c) if present
	if payloadOffset < len(payload) && payload[payloadOffset] == 0x6c {
		userInfoData := payload[payloadOffset:]
		// Handle user information if needed
		// You can add parsing logic here if required
		fmt.Printf(" MAP data parsed %+v", userInfoData)

	}

	return nil
}*/
// Change the function signature to return userInfoData
/*func (t *TCAP) UnmarshalBinary(b []byte) ([]byte, error) {
	var err error
	var offset = 0

	t.Transaction, err = ParseTransaction(b[offset:])
	if err != nil {
		fmt.Printf(" 1 tcap err returning from here")
		return nil, err
	}
	if len(t.Transaction.Payload) == 0 {
		return nil, nil
	}

	// Parse the payload sequentially
	payload := t.Transaction.Payload
	payloadOffset := 0

	// Check for Component Portion first (0x6b)
	if payload[payloadOffset] == 0x6b {
		componentLength := int(payload[payloadOffset+1])

		// Extract component data
		componentData := payload[payloadOffset : payloadOffset+2+componentLength]
		t.Components, err = ParseComponents(componentData)
		if err != nil {
			fmt.Printf(" 3 tcap err returning from here")
			return nil, err
		}
		payloadOffset += 2 + componentLength
	}

	// Check for Dialogue Portion (0xa0) after components
	if payloadOffset < len(payload) && payload[payloadOffset] == 0xa0 {
		dialogueLength := int(payload[payloadOffset+1])

		// Extract dialogue data
		dialogueData := payload[payloadOffset : payloadOffset+2+dialogueLength]
		t.Dialogue, err = ParseDialogue(dialogueData)
		if err != nil {
			fmt.Printf(" 2 tcap err returning from here")
			return nil, err
		}
		payloadOffset += 2 + dialogueLength
	}

	// Check for User Information (0x6c) if present and return it
	if payloadOffset < len(payload) && payload[payloadOffset] == 0x6c {
		userInfoData := payload[payloadOffset:]
		fmt.Printf(" MAP data parsed %+v", userInfoData)
		return userInfoData, nil // Return the user info data
	}

	// Return nil if no user info data found
	return nil, nil
}*/
/*last func (t *TCAP) UnmarshalBinary(b []byte) ([]byte, error) {
	var err error
	var offset = 0

	t.Transaction, err = ParseTransaction(b[offset:])
	if err != nil {
		fmt.Printf("Failed to parse transaction: %v\n", err)
		return nil, err
	}

	if len(t.Transaction.Payload) == 0 {
		return nil, nil
	}

	payload := t.Transaction.Payload
	payloadOffset := 0

	// Check for Dialogue Portion FIRST (tag 0x6b)
	if payloadOffset < len(payload) && payload[payloadOffset] == 0x6b {
		// Parse the length field properly
		lengthOffset := payloadOffset + 1

		if lengthOffset >= len(payload) {
			fmt.Printf("Warning: dialogue tag found but no length byte\n")
			payloadOffset++
			goto parseComponents
		}

		var dialogueLength int
		var headerSize int

		lengthByte := payload[lengthOffset]

		if lengthByte&0x80 == 0 {
			// Short form: length is in the byte itself
			dialogueLength = int(lengthByte)
			headerSize = 2 // tag + 1 length byte
		} else {
			// Long form: lower 7 bits indicate number of length octets
			numLengthOctets := int(lengthByte & 0x7F)

			if numLengthOctets == 0 || numLengthOctets > 4 {
				fmt.Printf("Warning: invalid dialogue length encoding: %d octets\n", numLengthOctets)
				payloadOffset++
				goto parseComponents
			}

			if lengthOffset+numLengthOctets >= len(payload) {
				fmt.Printf("Warning: not enough bytes for dialogue length field\n")
				payloadOffset++
				goto parseComponents
			}

			// Decode multi-byte length
			dialogueLength = 0
			for i := 0; i < numLengthOctets; i++ {
				dialogueLength = (dialogueLength << 8) | int(payload[lengthOffset+1+i])
			}
			headerSize = 1 + 1 + numLengthOctets // tag + length indicator + length octets
		}

		// Validate we have enough data
		totalDialogueSize := headerSize + dialogueLength
		if payloadOffset+totalDialogueSize > len(payload) {
			fmt.Printf("Warning: dialogue portion declares %d bytes but only %d available\n",
				totalDialogueSize, len(payload)-payloadOffset)
			// Skip dialogue and try components
			payloadOffset++
			goto parseComponents
		}

		// Extract complete dialogue data including tag and length
		dialogueData := payload[payloadOffset : payloadOffset+totalDialogueSize]

		fmt.Printf("Attempting to parse dialogue: tag=0x%02x, length=%d, headerSize=%d, totalSize=%d\n",
			payload[payloadOffset], dialogueLength, headerSize, totalDialogueSize)
		fmt.Printf("Dialogue bytes: %x\n", dialogueData)

		t.Dialogue, err = ParseDialogue(dialogueData)
		if err != nil {
			fmt.Printf("Warning: failed to parse Dialogue: %v\n", err)
			fmt.Printf("Dialogue data that failed: %x\n", dialogueData)
			t.Dialogue = nil
		}

		payloadOffset += totalDialogueSize
	}

parseComponents:
	//  Check for Component Portion SECOND (tag 0x6c)
	if payloadOffset < len(payload) && payload[payloadOffset] == 0x6c {
		componentLength := int(payload[payloadOffset+1])

		// Validate we have enough data
		if payloadOffset+2+componentLength > len(payload) {
			return nil, fmt.Errorf("component portion length exceeds payload")
		}

		componentData := payload[payloadOffset : payloadOffset+2+componentLength]
		t.Components, err = ParseComponents(componentData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse components: %w", err)
		}
		payloadOffset += 2 + componentLength
	}

	// Return any remaining user data
	if payloadOffset < len(payload) {
		return payload[payloadOffset:], nil
	}

	return nil, nil
}
*/
func (t *TCAP) UnmarshalBinary(b []byte) ([]byte, error) {
	var err error
	var offset = 0

	t.Transaction, err = ParseTransaction(b[offset:])
	if err != nil {
		fmt.Printf("Failed to parse transaction: %v\n", err)
		return nil, err
	}

	if len(t.Transaction.Payload) == 0 {
		return nil, nil
	}

	payload := t.Transaction.Payload
	payloadOffset := 0

	// ✅ Check for Dialogue Portion FIRST (tag 0x6b) - SKIP IT
	if payloadOffset < len(payload) && payload[payloadOffset] == 0x6b {
		lengthOffset := payloadOffset + 1

		if lengthOffset >= len(payload) {
			fmt.Printf("Warning: dialogue tag found but no length byte\n")
			payloadOffset++
			goto parseComponents
		}

		var dialogueLength int
		lengthByte := payload[lengthOffset]

		if lengthByte&0x80 == 0 {
			// Short form
			dialogueLength = int(lengthByte)
			payloadOffset += 2 + dialogueLength
		} else {
			// Long form
			numLengthOctets := int(lengthByte & 0x7F)

			if numLengthOctets == 0 || numLengthOctets > 4 {
				fmt.Printf("Warning: invalid dialogue length encoding\n")
				payloadOffset++
				goto parseComponents
			}

			if lengthOffset+numLengthOctets >= len(payload) {
				fmt.Printf("Warning: not enough bytes for dialogue length\n")
				payloadOffset++
				goto parseComponents
			}

			dialogueLength = 0
			for i := 0; i < numLengthOctets; i++ {
				dialogueLength = (dialogueLength << 8) | int(payload[lengthOffset+1+i])
			}
			payloadOffset += 2 + numLengthOctets + dialogueLength
		}

		fmt.Printf("⏭️  Skipped dialogue portion (%d bytes), now at offset %d\n",
			dialogueLength, payloadOffset)

		// ✅ Create minimal dialogue object to pass nil checks
		t.Dialogue = &Dialogue{
			Tag:    0x6b,
			Length: uint8(dialogueLength),
		}
	}

parseComponents:
	// ✅ Check for Component Portion (tag 0x6c)
	if payloadOffset < len(payload) && payload[payloadOffset] == 0x6c {
		fmt.Printf("✓ Found component portion at offset %d\n", payloadOffset)

		componentLength := int(payload[payloadOffset+1])

		if payloadOffset+2+componentLength > len(payload) {
			return nil, fmt.Errorf("component portion length exceeds payload")
		}

		componentData := payload[payloadOffset : payloadOffset+2+componentLength]
		fmt.Printf("Component data (%d bytes): %x\n", len(componentData), componentData)

		t.Components, err = ParseComponents(componentData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse components: %w", err)
		}

		payloadOffset += 2 + componentLength

		// ✅ Return the MAP data from component parameter
		if t.Components != nil && len(t.Components.Component) > 0 {
			if t.Components.Component[0].Parameter != nil {
				mapData := t.Components.Component[0].Parameter.Value
				fmt.Printf("✓ Extracted MAP data (%d bytes): %x\n", len(mapData), mapData)
				return mapData, nil
			}
		}
	} else {
		fmt.Printf("⚠️  No component portion found at offset %d (tag: 0x%02x)\n",
			payloadOffset, payload[payloadOffset])
	}

	return nil, nil
}

// ParseBer parses given byte sequence as a TCAP.
//
// Deprecated: use ParseBER instead.
func ParseBer(b []byte) ([]*TCAP, error) {
	return ParseBER(b)
}

// ParseBER parses given byte sequence as a TCAP.
func ParseBER(b []byte) ([]*TCAP, error) {
	parsed, err := ParseAsBER(b)
	if err != nil {
		return nil, err
	}

	tcaps := make([]*TCAP, len(parsed))
	for i, tx := range parsed {
		t := &TCAP{
			Transaction: &Transaction{},
		}

		if err := t.Transaction.SetValsFrom(tx); err != nil {
			return nil, err
		}

		for _, dx := range tx.IE {
			switch dx.Tag {
			case 0x6b:
				t.Dialogue = &Dialogue{}
				if err := t.Dialogue.SetValsFrom(dx); err != nil {
					return nil, err
				}
			case 0x6c:
				t.Components = &Components{}
				if err := t.Components.SetValsFrom(dx); err != nil {
					return nil, err
				}
			}
		}

		tcaps[i] = t
	}

	return tcaps, nil
}

// MarshalLen returns the serial length of TCAP.
func (t *TCAP) MarshalLen() int {
	l := 0
	if portion := t.Components; portion != nil {
		l += portion.MarshalLen()
	}
	if portion := t.Dialogue; portion != nil {
		l += portion.MarshalLen()
	}
	if portion := t.Transaction; portion != nil {
		l += portion.MarshalLen()
	}
	return l
}

// SetLength sets the length in Length field.
func (t *TCAP) SetLength() {
	if portion := t.Components; portion != nil {
		portion.SetLength()
	}
	if portion := t.Dialogue; portion != nil {
		portion.SetLength()
	}
	if portion := t.Transaction; portion != nil {
		portion.SetLength()
		if c := t.Components; c != nil {
			portion.Length += uint8(c.MarshalLen())
		}
		if d := t.Dialogue; d != nil {
			portion.Length += uint8(d.MarshalLen())
		}
	}
}

// OTID returns the TCAP Originating Transaction ID in Transaction Portion in uint32.
func (t *TCAP) OTID() uint32 {
	if ts := t.Transaction; ts != nil {
		if otid := ts.OrigTransactionID; otid != nil {
			return binary.BigEndian.Uint32(otid.Value)
		}
	}

	return 0
}

// DTID returns the TCAP Originating Transaction ID in Transaction Portion in uint32.
func (t *TCAP) DTID() uint32 {
	if ts := t.Transaction; ts != nil {
		if dtid := ts.DestTransactionID; dtid != nil {
			return binary.BigEndian.Uint32(dtid.Value)
		}
	}

	return 0
}

// AppContextName returns the ACN in string.
func (t *TCAP) AppContextName() string {
	if d := t.Dialogue; d != nil {
		return d.Context()
	}

	return ""
}

// AppContextNameWithVersion returns the ACN with ACN Version in string.
//
// TODO: Looking for a better way to return the value in the same format...
func (t *TCAP) AppContextNameWithVersion() string {
	if d := t.Dialogue; d != nil {
		return d.Context() + "-v" + d.ContextVersion()
	}

	return ""
}

// AppContextNameOid returns the ACN with ACN Version in OID formatted string.
//
// TODO: Looking for a better way to return the value in the same format...
/*func (t *TCAP) AppContextNameOid() string {
	if r := t.Dialogue; r != nil {
		if rp := r.DialoguePDU; rp != nil {
			var oid = "0."
			for i, x := range rp.ApplicationContextName.Value[2:] {
				oid += fmt.Sprint(x)
				if i <= 6 {
					break
				}
				oid += "."
			}
			return oid
		}
	}

	return ""
}*/

func (t *TCAP) AppContextNameOid() string {
	if r := t.Dialogue; r != nil {
		if rp := r.DialoguePDU; rp != nil {
			if rp.ApplicationContextName == nil || len(rp.ApplicationContextName.Value) < 2 {
				return ""
			}

			var oid = "0."
			for i, x := range rp.ApplicationContextName.Value[2:] {
				oid += fmt.Sprint(x)
				if i < len(rp.ApplicationContextName.Value[2:])-1 { // ✅ Fixed condition
					oid += "."
				}
			}
			return oid
		}
	}
	return ""
}

// ComponentType returns the ComponentType in Component Portion in the list of string.
//
// The returned value is of type []string, as it may have multiple Components.
func (t *TCAP) ComponentType() []string {
	if c := t.Components; c != nil {
		var iids []string
		for _, cm := range c.Component {
			iids = append(iids, cm.ComponentTypeString())
		}
		return iids
	}

	return nil
}

// InvokeID returns the InvokeID in Component Portion in the list of string.
//
// The returned value is of type []string, as it may have multiple Components.
func (t *TCAP) InvokeID() []uint8 {
	if c := t.Components; c != nil {
		var iids []uint8
		for _, cm := range c.Component {
			iids = append(iids, cm.InvID())
		}

		return iids
	}

	return nil
}

// OpCode returns the OpCode in Component Portion in the list of string.
//
// The returned value is of type []string, as it may have multiple Components.
func (t *TCAP) OpCode() []uint8 {
	if c := t.Components; c != nil {
		var ops []uint8
		for _, cm := range c.Component {
			ops = append(ops, cm.OpCode())
		}

		return ops
	}

	return nil
}

// LayerPayload returns the upper layer as byte slice.
//
// The returned value is of type [][]byte, as it may have multiple Components.
func (t *TCAP) LayerPayload() [][]byte {
	if c := t.Components; c != nil {
		var ret [][]byte
		for _, cm := range c.Component {
			ret = append(ret, cm.Parameter.Value)
		}

		return ret
	}

	return nil
}

// String returns TCAP in human readable string.
func (t *TCAP) String() string {
	return fmt.Sprintf("{Transaction: %v, Dialogue: %v, Components: %v}",
		t.Transaction,
		t.Dialogue,
		t.Components,
	)
}

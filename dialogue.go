// Copyright 2019-2024 go-tcap authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package tcap

import (
	"fmt"
	"io"
)

// Dialogue OID: Dialogue-As-ID and Unidialogue-As-Id.
const (
	DialogueAsID uint8 = iota + 1
	UnidialogueAsID
)

// Dialogue represents a Dialogue Portion of TCAP.
type Dialogue struct {
	Tag              Tag
	Length           uint8
	ExternalTag      Tag
	ExternalLength   uint8
	ObjectIdentifier *IE
	SingleAsn1Type   *IE
	DialoguePDU      *DialoguePDU
	Payload          []byte
}

// NewDialogue creates a new Dialogue with the DialoguePDU given.
func NewDialogue(oid, ver uint8, pdu *DialoguePDU, payload []byte) *Dialogue {
	d := &Dialogue{
		Tag:         NewApplicationWideConstructorTag(11),
		ExternalTag: NewUniversalConstructorTag(8),
		ObjectIdentifier: &IE{
			Tag:    NewUniversalPrimitiveTag(6),
			Length: 7,
			Value:  []byte{0, 17, 134, 5, 1, oid, ver},
		},
		SingleAsn1Type: &IE{
			Tag:    NewContextSpecificConstructorTag(0),
			Length: uint8(pdu.MarshalLen()),
		},
		DialoguePDU: pdu,
		Payload:     payload,
	}
	d.SetLength()

	return d
}

// MarshalBinary returns the byte sequence generated from a Dialogue.
func (d *Dialogue) MarshalBinary() ([]byte, error) {
	b := make([]byte, d.MarshalLen())
	if err := d.MarshalTo(b); err != nil {
		return nil, fmt.Errorf("failed to marshal Dialogue: %w", err)
	}
	return b, nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
func (d *Dialogue) MarshalTo(b []byte) error {
	if len(b) < 4 {
		return io.ErrUnexpectedEOF
	}
	b[0] = uint8(d.Tag)
	b[1] = d.Length
	b[2] = uint8(d.ExternalTag)
	b[3] = d.ExternalLength

	var offset = 4
	if field := d.ObjectIdentifier; field != nil {
		if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
			return err
		}
		offset += field.MarshalLen()
	}

	if d.SingleAsn1Type == nil {
		copy(b[offset:], d.Payload)
		return nil
	}

	if field := d.DialoguePDU; field != nil {
		d.SingleAsn1Type.Value = make([]byte, field.MarshalLen())
		if err := field.MarshalTo(d.SingleAsn1Type.Value); err != nil {
			return err
		}
	}

	d.SingleAsn1Type.SetLength()
	if err := d.SingleAsn1Type.MarshalTo(b[offset : offset+d.SingleAsn1Type.MarshalLen()]); err != nil {
		return err
	}
	offset += d.SingleAsn1Type.MarshalLen()

	copy(b[offset:], d.Payload)

	return nil
}

// ParseDialogue parses given byte sequence as an Dialogue.
func ParseDialogue(b []byte) (*Dialogue, error) {
	d := &Dialogue{}
	if err := d.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return d, nil
}

/*func ParseDialogue(b []byte) (*Dialogue, error) {
	d := &Dialogue{}

	if len(b) < 2 {
		return nil, fmt.Errorf("dialogue data too short: %d bytes", len(b))
	}

	// Verify dialogue portion tag (0x6b)
	if b[0] != 0x6b {
		return nil, fmt.Errorf("invalid dialogue tag: 0x%02x", b[0])
	}

	// Parse length
	offset := 1
	var dialogueLength int

	if b[offset]&0x80 == 0 {
		dialogueLength = int(b[offset])
		offset++
	} else {
		numOctets := int(b[offset] & 0x7F)
		offset++
		dialogueLength = 0
		for i := 0; i < numOctets && offset < len(b); i++ {
			dialogueLength = (dialogueLength << 8) | int(b[offset])
			offset++
		}
	}

	// Validate length
	if offset+dialogueLength > len(b) {
		return nil, fmt.Errorf("dialogue length mismatch: declared=%d, available=%d",
			dialogueLength, len(b)-offset)
	}

	// Extract dialogue content
	dialogueContent := b[offset : offset+dialogueLength]

	// Check for External encoding (tag 0x28)
	if len(dialogueContent) > 0 && dialogueContent[0] == 0x28 {
		// Skip External wrapper and parse inner content
		extOffset := 1

		// Parse External length
		if dialogueContent[extOffset]&0x80 == 0 {
			extOffset++
		} else {
			numOctets := int(dialogueContent[extOffset] & 0x7F)
			extOffset += 1 + numOctets
		}

		// Now parse the actual dialogue PDU
		if extOffset < len(dialogueContent) {
			return parseDialoguePDU(dialogueContent[extOffset:], d)
		}
	}

	// Direct dialogue PDU (no External wrapper)
	return parseDialoguePDU(dialogueContent, d)
}

func parseDialoguePDU(data []byte, d *Dialogue) (*Dialogue, error) {
	offset := 0

	// Skip OID if present (tag 0x06)
	if offset < len(data) && data[offset] == 0x06 {
		oidLen := int(data[offset+1])
		offset += 2 + oidLen
	}

	// Look for context-specific tag (0xa0) containing AARQ
	if offset < len(data) && data[offset] == 0xa0 {
		offset++ // Skip tag

		// Parse length
		if data[offset]&0x80 == 0 {
			offset++
		} else {
			numOctets := int(data[offset] & 0x7F)
			offset += 1 + numOctets
		}

		// Parse AARQ (tag 0x60)
		if offset < len(data) && data[offset] == 0x60 {
			aarqLen := int(data[offset+1])
			if offset+2+aarqLen <= len(data) {
				aarqData := data[offset : offset+2+aarqLen]

				// Parse DialoguePDU
				dialoguePDU, err := ParseDialoguePDU(aarqData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse DialoguePDU: %w", err)
				}
				d.DialoguePDU = dialoguePDU

				return d, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid dialogue PDU found in data")
}*/

// UnmarshalBinary sets the values retrieved from byte sequence in an Dialogue.
/*func (d *Dialogue) UnmarshalBinary(b []byte) error {
	l := len(b)
	if l < 5 {
		return io.ErrUnexpectedEOF
	}

	d.Tag = Tag(b[0])
	d.Length = b[1]
	d.ExternalTag = Tag(b[2])
	d.ExternalLength = b[3]

	var err error
	var offset = 4
	d.ObjectIdentifier, err = ParseIE(b[offset:])
	if err != nil {
		return err
	}
	offset += d.ObjectIdentifier.MarshalLen()

	d.SingleAsn1Type, err = ParseIE(b[offset:])
	if err != nil {
		return err
	}
	offset += d.SingleAsn1Type.MarshalLen()

	d.DialoguePDU, err = ParseDialoguePDU(d.SingleAsn1Type.Value)
	if err != nil {
		return err
	}

	d.Payload = b[offset:]

	return nil
}
*/
func (d *Dialogue) UnmarshalBinary(b []byte) error {
	l := len(b)
	if l < 5 {
		return io.ErrUnexpectedEOF
	}

	d.Tag = Tag(b[0])
	d.Length = b[1]

	// Validate that we have enough data for the declared length
	if int(d.Length)+2 > l {
		return io.ErrUnexpectedEOF
	}

	d.ExternalTag = Tag(b[2])
	d.ExternalLength = b[3]

	// Validate external length
	if int(d.ExternalLength)+4 > l {
		return io.ErrUnexpectedEOF
	}

	var err error
	var offset = 4

	// Parse ObjectIdentifier with bounds checking
	if offset >= l {
		return io.ErrUnexpectedEOF
	}

	d.ObjectIdentifier, err = ParseIE(b[offset:])
	if err != nil {
		return fmt.Errorf("failed to parse ObjectIdentifier: %w", err)
	}

	objIdLen := d.ObjectIdentifier.MarshalLen()
	if offset+objIdLen > l {
		return io.ErrUnexpectedEOF
	}
	offset += objIdLen

	// Parse SingleAsn1Type with bounds checking
	if offset >= l {
		return io.ErrUnexpectedEOF
	}

	d.SingleAsn1Type, err = ParseIE(b[offset:])
	if err != nil {
		return fmt.Errorf("failed to parse SingleAsn1Type: %w", err)
	}

	singleAsnLen := d.SingleAsn1Type.MarshalLen()
	if offset+singleAsnLen > l {
		return io.ErrUnexpectedEOF
	}
	offset += singleAsnLen

	// Parse DialoguePDU with error handling
	if d.SingleAsn1Type.Value != nil && len(d.SingleAsn1Type.Value) > 0 {
		d.DialoguePDU, err = ParseDialoguePDU(d.SingleAsn1Type.Value)
		if err != nil {
			// Log the error but don't fail completely - some dialogues might not have valid PDU
			fmt.Printf("Warning: failed to parse DialoguePDU: %v\n", err)
			d.DialoguePDU = nil
		}
	}

	// Set remaining payload
	if offset < l {
		d.Payload = b[offset:]
	} else {
		d.Payload = nil
	}

	return nil
}

// SetValsFrom sets the values from IE parsed by ParseBER.
func (d *Dialogue) SetValsFrom(berParsed *IE) error {
	d.Tag = berParsed.Tag
	d.Length = berParsed.Length
	for _, ie := range berParsed.IE {
		var dpdu *IE
		if ie.Tag == 0x28 {
			d.ExternalTag = ie.Tag
			d.ExternalLength = ie.Length
			for _, iex := range ie.IE {
				switch iex.Tag {
				case 0x06:
					d.ObjectIdentifier = iex
				case 0xa0:
					d.SingleAsn1Type = iex
					dpdu = iex.IE[0]
				}
			}
		}

		switch dpdu.Tag.Code() {
		case AARQ, AARE, ABRT:
			d.DialoguePDU = &DialoguePDU{
				Type:   dpdu.Tag,
				Length: dpdu.Length,
			}
		}
		for _, iex := range dpdu.IE {
			switch iex.Tag {
			case 0x80:
				d.DialoguePDU.ProtocolVersion = iex
			case 0xa1:
				d.DialoguePDU.ApplicationContextName = iex
			case 0xa2:
				d.DialoguePDU.Result = iex
			case 0xa3:
				d.DialoguePDU.ResultSourceDiagnostic = iex
			}
		}
	}
	return nil
}

// MarshalLen returns the serial length of Dialogue.
func (d *Dialogue) MarshalLen() int {
	l := 4
	if field := d.ObjectIdentifier; field != nil {
		l += field.MarshalLen()
	}
	if field := d.DialoguePDU; field != nil {
		l += field.MarshalLen() + 2 // 2 = singleAsn1Type IE Header
	}

	return l + len(d.Payload)
}

// SetLength sets the length in Length field.
func (d *Dialogue) SetLength() {
	if d.ObjectIdentifier != nil {
		d.ObjectIdentifier.SetLength()
	}
	if d.DialoguePDU != nil {
		d.DialoguePDU.SetLength()
	}

	d.Length = uint8(d.MarshalLen() - 2)
	d.ExternalLength = uint8(d.MarshalLen() - 4)
}

// String returns the SCCP common header values in human readable format.
func (d *Dialogue) String() string {
	return fmt.Sprintf("{Tag: %#x, Length: %d, ExternalTag: %x, ExternalLength: %d, ObjectIdentifier: %v, SingleAsn1Type: %v, DialoguePDU: %v, Payload: %x}",
		d.Tag,
		d.Length,
		d.ExternalTag,
		d.ExternalLength,
		d.ObjectIdentifier,
		d.SingleAsn1Type,
		d.DialoguePDU,
		d.Payload,
	)
}

// Version returns Protocol Version in string.
func (d *Dialogue) Version() string {
	if d.DialoguePDU == nil {
		return ""
	}

	return d.DialoguePDU.Version()
}

// Context returns the Context part of ApplicationContextName in string.
func (d *Dialogue) Context() string {
	if d.DialoguePDU == nil {
		return ""
	}

	return d.DialoguePDU.Context()
}

// ContextVersion returns the Version part of ApplicationContextName in string.
func (d *Dialogue) ContextVersion() string {
	if d.DialoguePDU == nil {
		return ""
	}

	return d.DialoguePDU.ContextVersion()
}

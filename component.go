// Copyright 2019-2024 go-tcap authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package tcap

import (
	"fmt"
	"io"
)

// Component Type definitions.
const (
	Invoke int = iota + 1
	ReturnResultLast
	ReturnError
	Reject
	_
	_
	ReturnResultNotLast
)

// Problem Type definitions.
const (
	GeneralProblem int = iota
	InvokeProblem
	ReturnResultProblem
	ReturnErrorProblem
)

// General Problem Code definitions.
const (
	UnrecognizedComponent uint8 = iota
	MistypedComponent
	BadlyStructuredComponent
)

// Invoke Problem Code definitions.
const (
	InvokeProblemDuplicateInvokeID uint8 = iota
	InvokeProblemUnrecognizedOperation
	InvokeProblemMistypedParameter
	InvokeProblemResourceLimitation
	InvokeProblemInitiatingRelease
	InvokeProblemUnrecognizedLinkedID
	InvokeProblemLinkedResponseUnexpected
	InvokeProblemUnexpectedLinkedOperation
)

// ReturnResult Problem Code definitions.
const (
	ResultProblemUnrecognizedInvokeID uint8 = iota
	ResultProblemReturnResultUnexpected
	ResultProblemMistypedParameter
)

// ReturnError Problem Code definitions.
const (
	ErrorProblemUnrecognizedInvokeID uint8 = iota
	ErrorProblemReturnErrorUnexpected
	ErrorProblemUnrecognizedError
	ErrorProblemUnexpectedError
	ErrorProblemMistypedParameter
)

// Components represents a TCAP Components(Header).
//
// This is a TCAP Components' Header part. Contents are in Component field.
type Components struct {
	Tag       Tag
	Length    uint8
	Component []*Component
}

// Component represents a TCAP Component.
type Component struct {
	Type          Tag
	Length        uint8
	InvokeID      *IE
	LinkedID      *IE
	ResultRetres  *IE
	SequenceTag   *IE
	OperationCode *IE
	ErrorCode     *IE
	ProblemCode   *IE
	Parameter     *IE
}

// NewComponents creates a new Components.
func NewComponents(comps ...*Component) *Components {
	c := &Components{
		Tag:       NewApplicationWideConstructorTag(12),
		Component: comps,
	}
	c.SetLength()

	return c
}

// NewInvoke returns a new single Invoke Component.
func NewInvoke(invID int, lkID int, opCode uint8, isLocal bool, param []byte) *Component {
	c := &Component{
		Type: NewContextSpecificConstructorTag(Invoke),
		InvokeID: &IE{
			Tag:    NewUniversalPrimitiveTag(2),
			Length: 1,
			Value:  []byte{uint8(invID)},
		},
		OperationCode: NewOperationCode(opCode, isLocal),
	}

	if lkID > 0 {
		c.LinkedID = &IE{
			Tag:    NewContextSpecificPrimitiveTag(0),
			Length: 1,
			Value:  []byte{uint8(lkID)},
		}
	}

	if param != nil {
		if err := c.setParameterFromBytes(param); err != nil {
			logf("failed to build Parameter: %v", err)
		}
	}

	c.SetLength()
	return c
}

// NewReturnResult returns a new single ReturnResultLast or ReturnResultNotLast Component.
func NewReturnResult(invID int, opCode uint8, isLocal, isLast bool, param []byte) *Component {
	tag := ReturnResultNotLast
	if isLast {
		tag = ReturnResultLast
	}

	c := &Component{
		Type: NewContextSpecificConstructorTag(tag),
		InvokeID: &IE{
			Tag:    NewUniversalPrimitiveTag(2),
			Length: 1,
			Value:  []byte{uint8(invID)},
		},
		OperationCode: NewOperationCode(opCode, isLocal),
	}

	if param != nil {
		if err := c.setParameterFromBytes(param); err != nil {
			logf("failed to build Parameter: %v", err)
		}
	}

	c.SetLength()
	return c
}

// NewReturnError returns a new single ReturnError Component.
func NewReturnError(invID, errCode uint8, isLocal bool, param []byte) *Component {
	c := &Component{
		Type: NewContextSpecificConstructorTag(ReturnError),
		InvokeID: &IE{
			Tag:    NewUniversalPrimitiveTag(2),
			Length: 1,
			Value:  []byte{uint8(invID)},
		},
		ErrorCode: NewErrorCode(errCode, isLocal),
	}

	if param != nil {
		if err := c.setParameterFromBytes(param); err != nil {
			logf("failed to build Parameter: %v", err)
		}
	}

	c.SetLength()
	return c
}

// NewReject returns a new single Reject Component.
func NewReject(invID, problemType int, problemCode uint8, param []byte) *Component {
	c := &Component{
		Type: NewContextSpecificConstructorTag(Invoke),
		InvokeID: &IE{
			Tag:    NewUniversalPrimitiveTag(2),
			Length: 1,
			Value:  []byte{uint8(invID)},
		},
		ProblemCode: &IE{
			Tag:    NewContextSpecificPrimitiveTag(problemType),
			Length: 1,
			Value:  []byte{problemCode},
		},
	}

	if param != nil {
		if err := c.setParameterFromBytes(param); err != nil {
			logf("failed to build Parameter: %v", err)
		}
	}

	c.SetLength()
	return c
}

// NewOperationCode returns a Operation Code.
func NewOperationCode(code uint8, isLocal bool) *IE {
	var tag = 6
	if isLocal {
		tag = 2
	}
	return &IE{
		Tag:    NewUniversalPrimitiveTag(tag),
		Length: 1,
		Value:  []byte{uint8(code)},
	}
}

// NewErrorCode returns a Error Code.
func NewErrorCode(code uint8, isLocal bool) *IE {
	return NewOperationCode(code, isLocal)
}

// MarshalBinary returns the byte sequence generated from a Components instance.
func (c *Components) MarshalBinary() ([]byte, error) {
	b := make([]byte, c.MarshalLen())
	if err := c.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}
func (c *Components) MarshalTo(b []byte) error {
	b[0] = uint8(c.Tag)

	cursor := 2
	for _, comp := range c.Component {
		compLen := comp.MarshalLen()
		if err := comp.MarshalTo(b[cursor : cursor+compLen]); err != nil {
			return err
		}
		cursor += compLen
	}

	actualLength := cursor - 2

	if actualLength < 128 {
		b[1] = byte(actualLength)
	} else if actualLength <= 255 {

		copy(b[3:3+(cursor-2)], b[2:cursor])
		b[1] = 0x81
		b[2] = byte(actualLength)
	} else {

		copy(b[4:4+(cursor-2)], b[2:cursor])
		b[1] = byte(actualLength >> 16)
		b[2] = byte(actualLength >> 8)
		b[3] = byte(actualLength)
	}

	return nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
func (c *Component) MarshalTo(b []byte) error {
	b[0] = uint8(c.Type)

	var offset = 2
	if field := c.InvokeID; field != nil {
		if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
			return err
		}
		offset += field.MarshalLen()
	}

	switch c.Type.Code() {
	case Invoke:
		if field := c.LinkedID; field != nil {
			if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
				return err
			}
			offset += field.MarshalLen()
		}

		if field := c.OperationCode; field != nil {
			if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
				return err
			}
			offset += field.MarshalLen()
		}

		if field := c.Parameter; field != nil {
			copy(b[offset:], field.Value)
			offset += len(field.Value)
		}

	case ReturnResultLast, ReturnResultNotLast:
		if c.OperationCode != nil || c.Parameter != nil {

			seqContentLen := 0

			if field := c.OperationCode; field != nil {
				seqContentLen += field.MarshalLen()
			}

			if field := c.Parameter; field != nil {
				seqContentLen += len(field.Value)
			}

			b[offset] = 0x30 // SEQUENCE tag
			offset++

			if seqContentLen < 128 {
				// Short form
				b[offset] = byte(seqContentLen)
				offset++
			} else if seqContentLen <= 255 {
				// Long form (1 byte)
				b[offset] = 0x81
				b[offset+1] = byte(seqContentLen)
				offset += 2
			} else {
				// Long form (2 bytes)
				b[offset] = 0x82
				b[offset+1] = byte(seqContentLen >> 8)
				b[offset+2] = byte(seqContentLen & 0xFF)
				offset += 3
			}

			if field := c.OperationCode; field != nil {
				if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
					return err
				}
				offset += field.MarshalLen()
			}

			if field := c.Parameter; field != nil {
				copy(b[offset:], field.Value)
				offset += len(field.Value)
			}
		}

	case ReturnError:
		if field := c.ErrorCode; field != nil {
			if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
				return err
			}
			offset += field.MarshalLen()
		}

		if field := c.Parameter; field != nil {
			if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
				return err
			}
			offset += field.MarshalLen()
		}

	case Reject:
		if field := c.ProblemCode; field != nil {
			if err := field.MarshalTo(b[offset : offset+field.MarshalLen()]); err != nil {
				return err
			}
		}
	}

	actualLength := offset - 2

	if actualLength < 128 {
		b[1] = byte(actualLength)
	} else if actualLength <= 255 {

		copy(b[3:3+(offset-2)], b[2:offset])
		b[1] = 0x81
		b[2] = byte(actualLength)
	} else {

		copy(b[4:4+(offset-2)], b[2:offset])
		b[1] = 0x82
		b[2] = byte(actualLength >> 8)
		b[3] = byte(actualLength & 0xFF)
	}

	return nil
}

// ParseComponents parses given byte sequence as an Components.
func ParseComponents(b []byte) (*Components, error) {
	c := &Components{}
	if err := c.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return c, nil
}

// UnmarshalBinary sets the values retrieved from byte sequence in an Components.
func (c *Components) UnmarshalBinary(b []byte) error {
	if len(b) < 2 {
		return io.ErrUnexpectedEOF
	}

	c.Tag = Tag(b[0])
	c.Length = b[1]

	var offset = 2
	for {
		if len(b) < 2 {
			break
		}

		comp, err := ParseComponent(b[offset:])
		if err != nil {
			return err
		}
		c.Component = append(c.Component, comp)

		if len(b[offset:]) == int(comp.Length)+2 {
			break
		}
		b = b[offset+comp.MarshalLen()-2:]
	}
	return nil
}

// ParseComponent parses given byte sequence as an Component.
func ParseComponent(b []byte) (*Component, error) {
	c := &Component{}
	if err := c.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return c, nil
}

// UnmarshalBinary sets the values retrieved from byte sequence in an Component.
func (c *Component) UnmarshalBinary(b []byte) error {
	if len(b) < 2 {
		return io.ErrUnexpectedEOF
	}
	c.Type = Tag(b[0])
	c.Length = b[1]

	var err error
	var offset = 2
	c.InvokeID, err = ParseIE(b[offset:])
	if err != nil {
		return err
	}
	offset += c.InvokeID.MarshalLen()

	switch c.Type.Code() {
	case Invoke:
		c.OperationCode, err = ParseIE(b[offset:])
		if err != nil {
			return err
		}
		offset += c.OperationCode.MarshalLen()

		if offset >= len(b) {
			return nil
		}
		c.Parameter, err = ParseIERecursive(b[offset:])
		if err != nil {
			return err
		}
	case ReturnResultLast, ReturnResultNotLast:
		c.ResultRetres, err = ParseIE(b[offset:])
		if err != nil {
			return err
		}
		offset = 0
		b = c.ResultRetres.Value[offset:]

		c.OperationCode, err = ParseIE(b[offset:])
		if err != nil {
			return err
		}
		offset += c.OperationCode.MarshalLen()

		if offset >= len(b) {
			return nil
		}
		c.Parameter, err = ParseIERecursive(b[offset:])
		if err != nil {
			return err
		}
	case ReturnError:
		c.ErrorCode, err = ParseIE(b[offset:])
		if err != nil {
			return err
		}
		offset += c.ErrorCode.MarshalLen()

		if offset >= len(b) {
			return nil
		}
		c.Parameter, err = ParseIERecursive(b[offset:])
		if err != nil {
			return err
		}
	case Reject:
		c.ProblemCode, err = ParseIE(b[offset:])
		if err != nil {
			return err
		}
	}
	return nil
}

// setParameterFromBytes sets the Parameter field from given bytes.
//
// It sets the value as it is if the given bytes cannot be parsed as (a set of) IE.
// func (c *Component) setParameterFromBytes(b []byte) error {
func (c *Component) setParameterFromBytes(b []byte) error {
	if b == nil {
		return io.ErrUnexpectedEOF
	}

	// Handle context-specific tags with long-form length encoding
	if len(b) >= 2 && (b[0] >= 0xa0 && b[0] <= 0xaf) {
		tag := b[0]
		lengthByte := b[1]

		var actualLength uint8
		var valueStart int

		if lengthByte < 0x80 {
			// Short form: length is in the byte itself
			actualLength = lengthByte
			valueStart = 2
		} else if lengthByte == 0x81 {
			// Long form (1 byte): next byte contains the length
			if len(b) < 3 {
				return fmt.Errorf("insufficient data for long-form length")
			}
			actualLength = b[2]
			valueStart = 3
		} else if lengthByte == 0x82 {
			// Long form (2 bytes): next 2 bytes contain the length
			if len(b) < 4 {
				return fmt.Errorf("insufficient data for 2-byte long-form length")
			}
			// For uint8 Length field, we can only store up to 255
			// If actual length > 255, truncate (this is a limitation of the IE struct)
			fullLength := int(b[2])<<8 | int(b[3])
			if fullLength > 255 {
				actualLength = 255
				logf("Warning: Length %d exceeds uint8, truncating to 255", fullLength)
			} else {
				actualLength = uint8(fullLength)
			}
			valueStart = 4
		} else {
			return fmt.Errorf("unsupported length encoding: 0x%02x", lengthByte)
		}

		value := b[valueStart:]

		c.Parameter = &IE{
			Tag:    Tag(tag),
			Length: actualLength,
			Value:  value,
		}

		logf("Extracted ASN.1 structure - Tag: 0x%02x, Length: %d (from encoding: 0x%02x), Value: %x",
			tag, actualLength, lengthByte, value[:min(20, len(value))])
		return nil
	}

	ies, err := ParseMultiIEs(b)
	if err != nil {
		logf("failed to parse given bytes, building it anyway: %v", err)
		c.Parameter = &IE{
			// TODO: tag should not be determined here.
			Tag:   NewUniversalConstructorTag(0x10),
			Value: b,
		}

		return nil
	}

	c.Parameter = &IE{
		// TODO: tag should not be determined here.
		Tag:   NewUniversalConstructorTag(0x10),
		Value: b,
		IE:    ies,
	}
	return nil
}

// SetValsFrom sets the values from IE parsed by ParseBER.
func (c *Components) SetValsFrom(berParsed *IE) error {
	c.Tag = berParsed.Tag
	c.Length = berParsed.Length
	for _, ie := range berParsed.IE {
		comp := &Component{
			Type:   ie.Tag,
			Length: ie.Length,
		}

		switch ie.Tag {
		case 0xa1: // Invoke
			for i, iex := range ie.IE {
				switch iex.Tag {
				case 0x02:
					if i == 0 {
						comp.InvokeID = iex
					} else {
						comp.OperationCode = iex
					}
				case 0x30:
					comp.Parameter = iex
				}
			}
		case 0xa2, 0xa7: // ReturnResult(Not)Last
			for i, iex := range ie.IE {
				switch iex.Tag {
				case 0x02:
					if i == 0 {
						comp.InvokeID = iex
					}
				case 0x30:
					comp.ResultRetres = iex
					for _, riex := range iex.IE {
						switch riex.Tag {
						case 0x02:
							comp.OperationCode = riex
						case 0x30:
							comp.Parameter = riex
						}
					}
				}
			}
		case 0xa3: // ReturnError
			for i, iex := range ie.IE {
				switch iex.Tag {
				case 0x02:
					if i == 0 {
						comp.InvokeID = iex
					} else {
						comp.ErrorCode = iex
					}
				case 0x30:
					comp.Parameter = iex
				}
			}
		}

		c.Component = append(c.Component, comp)
	}

	return nil
}

// MarshalLen returns the serial length of Components.
func (c *Components) MarshalLen() int {
	// Start with tag + length byte(s)
	contentLen := 0

	// Calculate total content length
	for _, comp := range c.Component {
		contentLen += comp.MarshalLen()
	}

	// Determine header size based on content length
	headerSize := 2 // Tag + 1 length byte (short form)

	if contentLen >= 128 && contentLen <= 255 {
		headerSize = 3 // Tag + 0x81 + 1 length byte
	} else if contentLen > 255 {
		headerSize = 4 // Tag + 0x82 + 2 length bytes
	}

	return headerSize + contentLen
}

// MarshalLen returns the serial length of Component.
func (c *Component) MarshalLen() int {
	// Start with InvokeID
	contentLen := c.InvokeID.MarshalLen()

	switch c.Type.Code() {
	case Invoke:
		if field := c.LinkedID; field != nil {
			contentLen += field.MarshalLen()
		}
		if field := c.OperationCode; field != nil {
			contentLen += field.MarshalLen()
		}
		if field := c.Parameter; field != nil {
			contentLen += len(field.Value)
		}
	case ReturnResultLast, ReturnResultNotLast:
		if c.OperationCode != nil || c.Parameter != nil {

			seqContentLen := 0

			if field := c.OperationCode; field != nil {
				seqContentLen += field.MarshalLen()
			}

			if field := c.Parameter; field != nil {
				seqContentLen += len(c.Parameter.Value)
			}
			fmt.Printf("MarshalLen: Parameter.Value length=%d, MarshalLen()=%d\n",
				len(c.Parameter.Value), c.Parameter.MarshalLen())

			seqHeaderSize := 2 // Tag + 1 length byte (short form)

			if seqContentLen >= 128 && seqContentLen <= 255 {
				seqHeaderSize = 3 // Tag + 0x81 + 1 length byte
			} else if seqContentLen > 255 {
				seqHeaderSize = 4 // Tag + 0x82 + 2 length bytes
			}
			contentLen += seqHeaderSize + seqContentLen
		}

	case ReturnError:
		if field := c.ErrorCode; field != nil {
			contentLen += field.MarshalLen()
		}
		if field := c.Parameter; field != nil {
			contentLen += field.MarshalLen()
		}

	case Reject:
		if field := c.ProblemCode; field != nil {
			contentLen += field.MarshalLen()
		}
	}

	headerSize := 2 // Tag + 1 length byte (short form)

	if contentLen >= 128 && contentLen <= 255 {
		headerSize = 3 // Tag + 0x81 + 1 length byte
	} else if contentLen > 255 {
		headerSize = 4 // Tag + 0x82 + 2 length bytes
	}

	return headerSize + contentLen
}

// SetLength sets the length in Length field.
func (c *Components) SetLength() {
	c.Length = 0
	for _, comp := range c.Component {
		comp.SetLength()
		c.Length += uint8(comp.MarshalLen())
	}
}
func (c *Component) SetLength() {
	// Set length for all child fields first
	if field := c.InvokeID; field != nil {
		field.SetLength()
	}
	if field := c.LinkedID; field != nil {
		field.SetLength()
	}
	if field := c.OperationCode; field != nil {
		field.SetLength()
	}
	if field := c.ErrorCode; field != nil {
		field.SetLength()
	}

	// For Invoke, Parameter.Length should be len(Value) not MarshalLen()
	if field := c.Parameter; field != nil {
		if c.Type.Code() == Invoke {
			// For Invoke, Parameter contains raw bytes (no tag/length wrapper)
			field.Length = uint8(len(field.Value))
		} else if c.Type.Code() == ReturnError {
			if field := c.Parameter; field != nil {
				field.SetLength()
			}
		} else {
			field.SetLength()
		}
	}
	if field := c.ProblemCode; field != nil {
		field.SetLength()
	}
	if field := c.SequenceTag; field != nil {
		field.SetLength()
	}
	if field := c.ResultRetres; field != nil {
		// For backward compatibility with parsing
		// Calculate content length for ResultRetres
		l := 0
		if c.OperationCode != nil {
			l += c.OperationCode.MarshalLen()
		}
		if c.Parameter != nil {
			l += len(c.Parameter.Value)
		}
		field.Length = uint8(l)
	}
	//  Use MarshalLen() which has the correct calculation
	// MarshalLen() already handles ReturnResult SEQUENCE wrapper correctly
	if c.Type.Code() == Invoke && c.Parameter != nil {
		fmt.Printf("Invoke Parameter: Value length=%d, MarshalLen=%d",
			len(c.Parameter.Value), c.Parameter.MarshalLen())
	}

	finalLen := c.MarshalLen() - 2
	fmt.Printf("Component SetLength: Type=0x%02x, Calculated=%d", c.Type, finalLen)
	c.Length = uint8(finalLen)
}

// ComponentTypeString returns the Component Type in string.
func (c *Component) ComponentTypeString() string {
	switch c.Type.Code() {
	case Invoke:
		return "invoke"
	case ReturnResultLast:
		return "returnResultLast"
	case ReturnError:
		return "returnError"
	case Reject:
		return "reject"
	case ReturnResultNotLast:
		return "returnResultNotLast"
	}
	return ""
}

// InvID returns the InvID in string.
func (c *Component) InvID() uint8 {
	if c.InvokeID != nil {
		return c.InvokeID.Value[0]
	}
	return 0
}

// OpCode returns the OpCode in string.
func (c *Component) OpCode() uint8 {
	if c.Type.Code() == ReturnError {
		return c.ErrorCode.Value[0]
	} else if c.Type.Code() != Reject {
		return c.OperationCode.Value[0]
	}
	return 0
}

// String returns Components in human readable string.
func (c *Components) String() string {
	return fmt.Sprintf("{Tag: %#x, Length: %d, Component: %v}",
		c.Tag,
		c.Length,
		c.Component,
	)
}

// String returns Component in human readable string.
func (c *Component) String() string {
	return fmt.Sprintf("{Type: %#x, Length: %d, ResultRetres: %v, InvokeID: %v, LinkedID: %v, OperationCode: %v, ErrorCode: %v, ProblemCode: %v, Parameter: %v}",
		c.Type,
		c.Length,
		c.ResultRetres,
		c.InvokeID,
		c.LinkedID,
		c.OperationCode,
		c.ErrorCode,
		c.ProblemCode,
		c.Parameter,
	)
}

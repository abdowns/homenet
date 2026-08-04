package nql

import "testing"

func TestReadRoundTrip(t *testing.T) {
	prog, err := Compile("", "schema T { a: u64 b: i32 c: f64 d: bool e: ip4 s: str }")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	defer prog.Close()
	schema, ok := prog.Schema("T")
	if !ok {
		t.Fatal("schema T not found")
	}

	buf := NewBuf(schema, 1)
	defer buf.Free()
	buf.SetUint(0, "a", 0xFFFFFFFFFFFFFFFF)
	buf.SetInt(0, "b", -42)
	buf.SetF64(0, "c", 3.5)
	buf.SetBool(0, "d", true)
	buf.SetIP4(0, "e", 10, 0, 0, 1)
	buf.SetStr(0, "s", "hello nql")

	rec := buf.Rec(0)
	fa, _ := schema.Field("a")
	fb, _ := schema.Field("b")
	fc, _ := schema.Field("c")
	fd, _ := schema.Field("d")
	fe, _ := schema.Field("e")
	fs, _ := schema.Field("s")

	if got := ReadUint(rec, fa); got != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("a: got %d", got)
	}
	if got := ReadInt(rec, fb); got != -42 {
		t.Errorf("b: got %d", got)
	}
	if got := ReadF64(rec, fc); got != 3.5 {
		t.Errorf("c: got %v", got)
	}
	if got := ReadBool(rec, fd); got != true {
		t.Errorf("d: got %v", got)
	}
	if got := ReadIP4(rec, fe); got != [4]byte{10, 0, 0, 1} {
		t.Errorf("e: got %v", got)
	}
	if got := ReadStr(rec, fs); got != "hello nql" {
		t.Errorf("s: got %q", got)
	}
}

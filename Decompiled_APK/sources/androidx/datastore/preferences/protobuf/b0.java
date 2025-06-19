package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public final class b0 extends Z {
    @Override // androidx.datastore.preferences.protobuf.Z
    public final a0 a(Object obj) {
        AbstractC1113u abstractC1113u = (AbstractC1113u) obj;
        a0 a0Var = abstractC1113u.unknownFields;
        if (a0Var != a0.f) {
            return a0Var;
        }
        a0 a0Var2 = new a0(0, new int[8], new Object[8], true);
        abstractC1113u.unknownFields = a0Var2;
        return a0Var2;
    }
}

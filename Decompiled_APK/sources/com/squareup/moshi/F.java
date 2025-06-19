package com.squareup.moshi;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Set;

/* loaded from: classes3.dex */
public final class F extends l {
    public final Class a;
    public final String[] b;
    public final Enum[] c;
    public final com.airbnb.lottie.parser.moshi.c d;

    public F(Class cls) throws NoSuchFieldException {
        this.a = cls;
        try {
            Enum[] enumArr = (Enum[]) cls.getEnumConstants();
            this.c = enumArr;
            this.b = new String[enumArr.length];
            int i = 0;
            while (true) {
                Enum[] enumArr2 = this.c;
                if (i >= enumArr2.length) {
                    this.d = com.airbnb.lottie.parser.moshi.c.b(this.b);
                    return;
                }
                String strName = enumArr2[i].name();
                String[] strArr = this.b;
                Field field = cls.getField(strName);
                Set set = com.squareup.moshi.internal.b.a;
                InterfaceC4853h interfaceC4853h = (InterfaceC4853h) field.getAnnotation(InterfaceC4853h.class);
                if (interfaceC4853h != null) {
                    String strName2 = interfaceC4853h.name();
                    if (!"\u0000".equals(strName2)) {
                        strName = strName2;
                    }
                }
                strArr[i] = strName;
                i++;
            }
        } catch (NoSuchFieldException e) {
            throw new AssertionError("Missing field in ".concat(cls.getName()), e);
        }
    }

    @Override // com.squareup.moshi.l
    public final Object a(p pVar) {
        int iL0 = pVar.l0(this.d);
        if (iL0 != -1) {
            return this.c[iL0];
        }
        String strJ = pVar.j();
        throw new JsonDataException("Expected one of " + Arrays.asList(this.b) + " but was " + pVar.P() + " at path " + strJ);
    }

    @Override // com.squareup.moshi.l
    public final void g(w wVar, Object obj) {
        wVar.C(this.b[((Enum) obj).ordinal()]);
    }

    public final String toString() {
        return assistantMode.refactored.a.i(this.a, new StringBuilder("JsonAdapter("), ")");
    }
}

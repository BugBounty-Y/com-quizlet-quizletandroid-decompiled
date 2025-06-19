package com.quizlet.remote.model.explanations.myexplanations;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteMyExplanationsSessionJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public RemoteMyExplanationsSessionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("personId", DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_ID, "platform", "timestamp", "active");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "personId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, DBSessionFields.Names.ITEM_TYPE);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, DBSessionFields.Names.ITEM_ID);
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.TYPE, m, "active");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i2 = -1;
        Boolean bool2 = bool;
        Long l = null;
        Integer num = null;
        Integer num2 = null;
        Long l2 = null;
        String str = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw b.k("personId", "personId", reader);
                    }
                    break;
                case 1:
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw b.k(DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_TYPE, reader);
                    }
                    break;
                case 2:
                    str = (String) this.d.a(reader);
                    if (str == null) {
                        throw b.k(DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_ID, reader);
                    }
                    break;
                case 3:
                    num2 = (Integer) this.c.a(reader);
                    if (num2 == null) {
                        throw b.k("platform", "platform", reader);
                    }
                    break;
                case 4:
                    l2 = (Long) this.b.a(reader);
                    if (l2 == null) {
                        throw b.k("timestampSec", "timestamp", reader);
                    }
                    break;
                case 5:
                    bool2 = (Boolean) this.e.a(reader);
                    if (bool2 == null) {
                        throw b.k("active", "active", reader);
                    }
                    i2 = -33;
                    break;
            }
        }
        reader.i();
        if (i2 == -33) {
            if (l == null) {
                throw b.e("personId", "personId", reader);
            }
            long jLongValue = l.longValue();
            if (num == null) {
                throw b.e(DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_TYPE, reader);
            }
            int iIntValue = num.intValue();
            if (str == null) {
                throw b.e(DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_ID, reader);
            }
            if (num2 == null) {
                throw b.e("platform", "platform", reader);
            }
            int iIntValue2 = num2.intValue();
            if (l2 != null) {
                return new RemoteMyExplanationsSession(jLongValue, iIntValue, str, iIntValue2, l2.longValue(), bool2.booleanValue());
            }
            throw b.e("timestampSec", "timestamp", reader);
        }
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            Class cls = b.c;
            Class cls2 = Integer.TYPE;
            Class cls3 = Long.TYPE;
            Class[] clsArr = {cls3, cls2, String.class, cls2, cls3, Boolean.TYPE, cls2, cls};
            i = i2;
            declaredConstructor = RemoteMyExplanationsSession.class.getDeclaredConstructor(clsArr);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        } else {
            i = i2;
        }
        if (l == null) {
            throw b.e("personId", "personId", reader);
        }
        if (num == null) {
            throw b.e(DBSessionFields.Names.ITEM_TYPE, DBSessionFields.Names.ITEM_TYPE, reader);
        }
        if (str == null) {
            throw b.e(DBSessionFields.Names.ITEM_ID, DBSessionFields.Names.ITEM_ID, reader);
        }
        if (num2 == null) {
            throw b.e("platform", "platform", reader);
        }
        if (l2 == null) {
            throw b.e("timestampSec", "timestamp", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, num, str, num2, l2, bool2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteMyExplanationsSession) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteMyExplanationsSession remoteMyExplanationsSession = (RemoteMyExplanationsSession) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteMyExplanationsSession == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("personId");
        Long lValueOf = Long.valueOf(remoteMyExplanationsSession.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBSessionFields.Names.ITEM_TYPE);
        Integer numValueOf = Integer.valueOf(remoteMyExplanationsSession.b);
        l lVar2 = this.c;
        lVar2.g(writer, numValueOf);
        writer.l(DBSessionFields.Names.ITEM_ID);
        this.d.g(writer, remoteMyExplanationsSession.c);
        writer.l("platform");
        AbstractC4178x.p(remoteMyExplanationsSession.d, lVar2, writer, "timestamp");
        Z.k(remoteMyExplanationsSession.e, lVar, writer, "active");
        this.e.g(writer, Boolean.valueOf(remoteMyExplanationsSession.f));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(RemoteMyExplanationsSession)", "toString(...)");
    }
}

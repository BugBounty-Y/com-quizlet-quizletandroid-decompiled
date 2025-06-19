package com.quizlet.remote.model.folderset;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
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
public final class RemoteFolderSetJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public RemoteFolderSetJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("clientId", "setId", "folderId", "timestamp", "isDeleted", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "lastModified", "isDirty");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.class, m, "localId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "setId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.class, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.TYPE, m, "isDirty");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i = -1;
        Boolean bool2 = bool;
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Long l4 = null;
        Boolean bool3 = null;
        Long l5 = null;
        Long l6 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    break;
                case 1:
                    l2 = (Long) this.c.a(reader);
                    if (l2 == null) {
                        throw b.k("setId", "setId", reader);
                    }
                    break;
                case 2:
                    l3 = (Long) this.c.a(reader);
                    if (l3 == null) {
                        throw b.k("folderId", "folderId", reader);
                    }
                    break;
                case 3:
                    l4 = (Long) this.b.a(reader);
                    break;
                case 4:
                    bool3 = (Boolean) this.d.a(reader);
                    break;
                case 5:
                    l5 = (Long) this.b.a(reader);
                    break;
                case 6:
                    l6 = (Long) this.b.a(reader);
                    break;
                case 7:
                    bool2 = (Boolean) this.e.a(reader);
                    if (bool2 == null) {
                        throw b.k("isDirty", "isDirty", reader);
                    }
                    i = -129;
                    break;
            }
        }
        reader.i();
        if (i == -129) {
            if (l2 == null) {
                throw b.e("setId", "setId", reader);
            }
            long jLongValue = l2.longValue();
            if (l3 != null) {
                return new RemoteFolderSet(l, jLongValue, l3.longValue(), l4, bool3, l5, l6, bool2.booleanValue());
            }
            throw b.e("folderId", "folderId", reader);
        }
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            Class cls = b.c;
            Class cls2 = Boolean.TYPE;
            Class cls3 = Long.TYPE;
            declaredConstructor = RemoteFolderSet.class.getDeclaredConstructor(Long.class, cls3, cls3, Long.class, Boolean.class, Long.class, Long.class, cls2, Integer.TYPE, cls);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l2 == null) {
            throw b.e("setId", "setId", reader);
        }
        if (l3 == null) {
            throw b.e("folderId", "folderId", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, l2, l3, l4, bool3, l5, l6, bool2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteFolderSet) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteFolderSet remoteFolderSet = (RemoteFolderSet) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteFolderSet == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("clientId");
        l lVar = this.b;
        lVar.g(writer, remoteFolderSet.a);
        writer.l("setId");
        Long lValueOf = Long.valueOf(remoteFolderSet.b);
        l lVar2 = this.c;
        lVar2.g(writer, lValueOf);
        writer.l("folderId");
        Z.k(remoteFolderSet.c, lVar2, writer, "timestamp");
        lVar.g(writer, remoteFolderSet.d);
        writer.l("isDeleted");
        this.d.g(writer, remoteFolderSet.e);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        lVar.g(writer, remoteFolderSet.f);
        writer.l("lastModified");
        lVar.g(writer, remoteFolderSet.g);
        writer.l("isDirty");
        this.e.g(writer, Boolean.valueOf(remoteFolderSet.h));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(RemoteFolderSet)", "toString(...)");
    }
}

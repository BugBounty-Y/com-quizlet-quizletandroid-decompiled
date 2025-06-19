package com.quizlet.remote.model.bookmark;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
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
public final class RemoteBookmarkJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public volatile Constructor e;

    public RemoteBookmarkJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("clientId", "personId", "folderId", "lastModified", "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.class, m, "localId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        Boolean bool2 = bool;
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Long l4 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
            } else if (iK0 == 1) {
                l2 = (Long) this.c.a(reader);
                if (l2 == null) {
                    throw b.k("userId", "personId", reader);
                }
            } else if (iK0 == 2) {
                l3 = (Long) this.c.a(reader);
                if (l3 == null) {
                    throw b.k("folderId", "folderId", reader);
                }
            } else if (iK0 == 3) {
                l4 = (Long) this.b.a(reader);
            } else if (iK0 == 4) {
                bool2 = (Boolean) this.d.a(reader);
                if (bool2 == null) {
                    throw b.k("isDeleted", "isDeleted", reader);
                }
                i = -17;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -17) {
            if (l2 == null) {
                throw b.e("userId", "personId", reader);
            }
            long jLongValue = l2.longValue();
            if (l3 == null) {
                throw b.e("folderId", "folderId", reader);
            }
            return new RemoteBookmark(l, jLongValue, l3.longValue(), l4, bool2.booleanValue());
        }
        Constructor declaredConstructor = this.e;
        if (declaredConstructor == null) {
            Class cls = b.c;
            Class cls2 = Boolean.TYPE;
            Class cls3 = Long.TYPE;
            declaredConstructor = RemoteBookmark.class.getDeclaredConstructor(Long.class, cls3, cls3, Long.class, cls2, Integer.TYPE, cls);
            this.e = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Constructor constructor = declaredConstructor;
        if (l2 == null) {
            throw b.e("userId", "personId", reader);
        }
        if (l3 == null) {
            throw b.e("folderId", "folderId", reader);
        }
        Object objNewInstance = constructor.newInstance(l, l2, l3, l4, bool2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteBookmark) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteBookmark remoteBookmark = (RemoteBookmark) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteBookmark == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("clientId");
        l lVar = this.b;
        lVar.g(writer, remoteBookmark.a);
        writer.l("personId");
        Long lValueOf = Long.valueOf(remoteBookmark.b);
        l lVar2 = this.c;
        lVar2.g(writer, lValueOf);
        writer.l("folderId");
        Z.k(remoteBookmark.c, lVar2, writer, "lastModified");
        lVar.g(writer, remoteBookmark.d);
        writer.l("isDeleted");
        this.d.g(writer, Boolean.valueOf(remoteBookmark.e));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteBookmark)", "toString(...)");
    }
}

package com.quizlet.remote.model.explanations.solution;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.RemoteSimpleImage;
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
public final class RemoteSolutionColumnImageJsonAdapter extends l {
    public final c a;
    public final l b;
    public volatile Constructor c;

    public RemoteSolutionColumnImageJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("large", "regular");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(RemoteSimpleImage.class, M.a, "large");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteSimpleImage remoteSimpleImage = null;
        RemoteSimpleImage remoteSimpleImage2 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteSimpleImage = (RemoteSimpleImage) this.b.a(reader);
                i = -2;
            } else if (iK0 == 1) {
                remoteSimpleImage2 = (RemoteSimpleImage) this.b.a(reader);
            }
        }
        reader.i();
        if (i == -2) {
            return new RemoteSolutionColumnImage(remoteSimpleImage, remoteSimpleImage2);
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = RemoteSolutionColumnImage.class.getDeclaredConstructor(RemoteSimpleImage.class, RemoteSimpleImage.class, Integer.TYPE, b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(remoteSimpleImage, remoteSimpleImage2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteSolutionColumnImage) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSolutionColumnImage remoteSolutionColumnImage = (RemoteSolutionColumnImage) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSolutionColumnImage == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("large");
        l lVar = this.b;
        lVar.g(writer, remoteSolutionColumnImage.a);
        writer.l("regular");
        lVar.g(writer, remoteSolutionColumnImage.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(RemoteSolutionColumnImage)", "toString(...)");
    }
}

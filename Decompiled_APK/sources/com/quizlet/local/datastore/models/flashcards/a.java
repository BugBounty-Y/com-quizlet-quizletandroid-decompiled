package com.quizlet.local.datastore.models.flashcards;

import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.f0;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements f0 {
    public static final a a = new a();

    @Override // androidx.datastore.core.f0
    public final Object a() {
        d dVarX = d.x();
        Intrinsics.checkNotNullExpressionValue(dVarX, "getDefaultInstance(...)");
        return dVarX;
    }

    @Override // androidx.datastore.core.f0
    public final Object b(InputStream inputStream) throws CorruptionException {
        try {
            d dVarZ = d.z(inputStream);
            Intrinsics.checkNotNullExpressionValue(dVarZ, "parseFrom(...)");
            return dVarZ;
        } catch (IOException e) {
            Intrinsics.checkNotNullParameter("Cannot read flashcards proto.", "message");
            throw new CorruptionException("Cannot read flashcards proto.", e);
        }
    }

    @Override // androidx.datastore.core.f0
    public final Unit c(Object obj, OutputStream outputStream) {
        ((d) obj).j(outputStream);
        return Unit.a;
    }
}

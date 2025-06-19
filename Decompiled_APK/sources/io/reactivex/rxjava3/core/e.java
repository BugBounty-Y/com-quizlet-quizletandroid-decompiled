package io.reactivex.rxjava3.core;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;

/* loaded from: classes3.dex */
public abstract class e implements org.reactivestreams.a {
    public static final int a = Math.max(1, Integer.getInteger("rx3.buffer-size", 128).intValue());

    public final void a(f fVar) {
        Objects.requireNonNull(fVar, "subscriber is null");
        try {
            b(fVar);
        } catch (NullPointerException e) {
            throw e;
        } catch (Throwable th) {
            x7.b(th);
            C7.c(th);
            NullPointerException nullPointerException = new NullPointerException("Actually not, but can't throw other exceptions due to RS");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    public abstract void b(f fVar);
}

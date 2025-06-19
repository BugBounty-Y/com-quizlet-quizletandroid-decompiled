package com.quizlet.local.datastore.models.flashcards;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;
import java.io.InputStream;

/* loaded from: classes3.dex */
public final class d extends AbstractC4027v {
    private static final d DEFAULT_INSTANCE;
    public static final int ONBOARDINGCOMPLETED_FIELD_NUMBER = 1;
    private static volatile X PARSER = null;
    public static final int RECORDONBOARDINGCOMPLETED_FIELD_NUMBER = 2;
    private boolean onboardingCompleted_;
    private boolean recordOnboardingCompleted_;

    static {
        d dVar = new d();
        DEFAULT_INSTANCE = dVar;
        AbstractC4027v.u(d.class, dVar);
    }

    public static void w(d dVar) {
        dVar.onboardingCompleted_ = true;
    }

    public static d x() {
        return DEFAULT_INSTANCE;
    }

    public static d z(InputStream inputStream) {
        return (d) AbstractC4027v.t(DEFAULT_INSTANCE, inputStream);
    }

    @Override // com.google.protobuf.AbstractC4027v
    public final Object l(int i) {
        X c4026u;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return (byte) 1;
            case 1:
                return null;
            case 2:
                return new C4007b0(DEFAULT_INSTANCE, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0000\u0000\u0001\u0007\u0002\u0007", new Object[]{"onboardingCompleted_", "recordOnboardingCompleted_"});
            case 3:
                return new d();
            case 4:
                return new c(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (d.class) {
                    try {
                        c4026u = PARSER;
                        if (c4026u == null) {
                            c4026u = new C4026u();
                            PARSER = c4026u;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return c4026u;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public final boolean y() {
        return this.onboardingCompleted_;
    }
}

package com.google.android.gms.internal.ads;

import com.google.android.gms.internal.play_billing.C3806j;
import java.io.Serializable;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class Wv {
    public final /* synthetic */ int a;
    public final String b;
    public volatile Logger c;
    public final Serializable d;

    public Wv(Class cls, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.d = new C3806j();
                this.b = cls.getName();
                break;
            default:
                this.d = new Ft();
                this.b = cls.getName();
                break;
        }
    }

    public final Logger a() {
        Logger logger;
        Logger logger2;
        switch (this.a) {
            case 0:
                Logger logger3 = this.c;
                if (logger3 != null) {
                    return logger3;
                }
                synchronized (((Ft) this.d)) {
                    try {
                        logger = this.c;
                        if (logger == null) {
                            logger = Logger.getLogger(this.b);
                            this.c = logger;
                        }
                    } finally {
                    }
                }
                return logger;
            default:
                Logger logger4 = this.c;
                if (logger4 != null) {
                    return logger4;
                }
                synchronized (((C3806j) this.d)) {
                    try {
                        logger2 = this.c;
                        if (logger2 == null) {
                            logger2 = Logger.getLogger(this.b);
                            this.c = logger2;
                        }
                    } finally {
                    }
                }
                return logger2;
        }
    }
}

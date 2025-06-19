package io.reactivex.rxjava3.schedulers;

import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.schedulers.n;
import io.reactivex.rxjava3.internal.schedulers.v;
import io.reactivex.rxjava3.internal.schedulers.w;
import java.util.Objects;

/* loaded from: classes3.dex */
public abstract class e {
    public static final o a;
    public static final o b;
    public static final o c;

    static {
        RuntimeException runtimeExceptionD;
        try {
            v vVar = d.a;
            Objects.requireNonNull(vVar, "Scheduler Supplier result can't be null");
            a = vVar;
            try {
                io.reactivex.rxjava3.internal.schedulers.d dVar = a.a;
                Objects.requireNonNull(dVar, "Scheduler Supplier result can't be null");
                b = dVar;
                try {
                    n nVar = b.a;
                    Objects.requireNonNull(nVar, "Scheduler Supplier result can't be null");
                    c = nVar;
                    int i = w.a;
                    try {
                        Objects.requireNonNull(c.a, "Scheduler Supplier result can't be null");
                    } finally {
                    }
                } finally {
                }
            } finally {
            }
        } finally {
        }
    }
}

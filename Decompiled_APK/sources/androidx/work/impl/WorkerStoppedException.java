package androidx.work.impl;

import java.util.concurrent.CancellationException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class WorkerStoppedException extends CancellationException {
    public final int a;

    public WorkerStoppedException(int i) {
        this.a = i;
    }
}

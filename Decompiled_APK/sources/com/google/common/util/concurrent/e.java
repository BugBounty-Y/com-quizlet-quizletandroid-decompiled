package com.google.common.util.concurrent;

import java.util.concurrent.Executor;
import java.util.concurrent.Future;

/* loaded from: classes2.dex */
public interface e extends Future {
    void a(Runnable runnable, Executor executor);
}

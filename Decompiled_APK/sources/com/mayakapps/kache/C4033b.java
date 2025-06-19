package com.mayakapps.kache;

import java.util.concurrent.CancellationException;

/* renamed from: com.mayakapps.kache.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4033b extends CancellationException {
    public final int a;

    public C4033b(int i) {
        super("The cached element was removed before creation");
        this.a = i;
    }
}

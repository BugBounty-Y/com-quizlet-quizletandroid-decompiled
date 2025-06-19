package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.ClipData;
import android.content.Intent;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.p0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3693p0 {
    public static final ClipData a = ClipData.newIntent("", new Intent());

    public static boolean a(int i, int i2) {
        return (i & i2) == i2;
    }
}

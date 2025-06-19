package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public final class R3 extends AbstractC2649tC {
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ R3(String str, int i) {
        super(str);
        this.i = i;
    }

    private final void e(ByteBuffer byteBuffer) {
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2649tC
    public final void c(ByteBuffer byteBuffer) {
        switch (this.i) {
            case 0:
                byteBuffer.position(byteBuffer.remaining() + byteBuffer.position());
                break;
        }
    }
}

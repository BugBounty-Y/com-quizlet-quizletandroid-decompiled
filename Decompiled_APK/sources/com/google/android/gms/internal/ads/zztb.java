package com.google.android.gms.internal.ads;

import android.media.MediaCodec;

/* loaded from: classes2.dex */
public class zztb extends zzhn {
    public final int a;

    public zztb(IllegalStateException illegalStateException, HE he) {
        int errorCode;
        super("Decoder failed: ".concat(String.valueOf(he == null ? null : he.a)), illegalStateException);
        if (illegalStateException instanceof MediaCodec.CodecException) {
            MediaCodec.CodecException codecException = (MediaCodec.CodecException) illegalStateException;
            codecException.getDiagnosticInfo();
            errorCode = codecException.getErrorCode();
        } else {
            errorCode = 0;
        }
        this.a = errorCode;
    }
}

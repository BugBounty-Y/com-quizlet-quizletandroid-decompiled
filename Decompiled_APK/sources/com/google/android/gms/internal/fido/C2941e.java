package com.google.android.gms.internal.fido;

import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;

/* renamed from: com.google.android.gms.internal.fido.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2941e extends AbstractC2940d {
    public final PublicKeyCredentialParameters a;

    public C2941e(PublicKeyCredentialParameters publicKeyCredentialParameters) {
        this.a = publicKeyCredentialParameters;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2940d
    public final Object a() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2940d
    public final boolean b() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C2941e) {
            return this.a.equals(((C2941e) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() + 1502476572;
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("Optional.of(", this.a.toString(), ")");
    }
}

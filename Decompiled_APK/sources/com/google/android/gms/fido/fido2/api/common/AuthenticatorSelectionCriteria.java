package com.google.android.gms.fido.fido2.api.common;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.fido.fido2.api.common.Attachment;
import com.google.android.gms.fido.fido2.api.common.ResidentKeyRequirement;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class AuthenticatorSelectionCriteria extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<AuthenticatorSelectionCriteria> CREATOR = new i(2);
    public final Attachment a;
    public final Boolean b;
    public final UserVerificationRequirement c;
    public final ResidentKeyRequirement d;

    public AuthenticatorSelectionCriteria(String str, String str2, Boolean bool, String str3) {
        Attachment attachmentA;
        ResidentKeyRequirement residentKeyRequirementA = null;
        if (str == null) {
            attachmentA = null;
        } else {
            try {
                attachmentA = Attachment.a(str);
            } catch (Attachment.UnsupportedAttachmentException | ResidentKeyRequirement.UnsupportedResidentKeyRequirementException | zzbc e) {
                throw new IllegalArgumentException(e);
            }
        }
        this.a = attachmentA;
        this.b = bool;
        this.c = str2 == null ? null : UserVerificationRequirement.a(str2);
        if (str3 != null) {
            residentKeyRequirementA = ResidentKeyRequirement.a(str3);
        }
        this.d = residentKeyRequirementA;
    }

    public final ResidentKeyRequirement a() {
        ResidentKeyRequirement residentKeyRequirement = this.d;
        if (residentKeyRequirement != null) {
            return residentKeyRequirement;
        }
        Boolean bool = this.b;
        if (bool == null || !bool.booleanValue()) {
            return null;
        }
        return ResidentKeyRequirement.RESIDENT_KEY_REQUIRED;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof AuthenticatorSelectionCriteria)) {
            return false;
        }
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = (AuthenticatorSelectionCriteria) obj;
        return u.l(this.a, authenticatorSelectionCriteria.a) && u.l(this.b, authenticatorSelectionCriteria.b) && u.l(this.c, authenticatorSelectionCriteria.c) && u.l(a(), authenticatorSelectionCriteria.a());
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.c, a()});
    }

    public final String toString() {
        String strValueOf = String.valueOf(this.a);
        String strValueOf2 = String.valueOf(this.c);
        String strValueOf3 = String.valueOf(this.d);
        StringBuilder sbY = android.support.v4.media.session.a.y("AuthenticatorSelectionCriteria{\n attachment=", strValueOf, ", \n requireResidentKey=");
        sbY.append(this.b);
        sbY.append(", \n requireUserVerification=");
        sbY.append(strValueOf2);
        sbY.append(", \n residentKeyRequirement=");
        return android.support.v4.media.session.a.t(sbY, strValueOf3, "\n }");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        Attachment attachment = this.a;
        AbstractC3489l3.h(parcel, 2, attachment == null ? null : attachment.a);
        Boolean bool = this.b;
        if (bool != null) {
            AbstractC3489l3.m(parcel, 3, 4);
            parcel.writeInt(bool.booleanValue() ? 1 : 0);
        }
        UserVerificationRequirement userVerificationRequirement = this.c;
        AbstractC3489l3.h(parcel, 4, userVerificationRequirement == null ? null : userVerificationRequirement.a);
        ResidentKeyRequirement residentKeyRequirementA = a();
        AbstractC3489l3.h(parcel, 5, residentKeyRequirementA != null ? residentKeyRequirementA.a : null);
        AbstractC3489l3.o(iN, parcel);
    }
}

package com.google.android.gms.auth.api.identity;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;

@Deprecated
/* loaded from: classes2.dex */
public final class BeginSignInRequest extends AbstractSafeParcelable {

    @NonNull
    public static final Parcelable.Creator<BeginSignInRequest> CREATOR = new b();
    public final PasswordRequestOptions a;
    public final GoogleIdTokenRequestOptions b;
    public final String c;
    public final boolean d;
    public final int e;
    public final PasskeysRequestOptions f;
    public final PasskeyJsonRequestOptions g;
    public final boolean h;

    @Deprecated
    public static final class GoogleIdTokenRequestOptions extends AbstractSafeParcelable {

        @NonNull
        public static final Parcelable.Creator<GoogleIdTokenRequestOptions> CREATOR = new d();
        public final boolean a;
        public final String b;
        public final String c;
        public final boolean d;
        public final String e;
        public final ArrayList f;
        public final boolean g;

        public GoogleIdTokenRequestOptions(boolean z, String str, String str2, boolean z2, String str3, ArrayList arrayList, boolean z3) {
            boolean z4 = true;
            if (z2 && z3) {
                z4 = false;
            }
            u.a("filterByAuthorizedAccounts and requestVerifiedPhoneNumber must not both be true; the Verified Phone Number feature only works in sign-ups.", z4);
            this.a = z;
            if (z) {
                u.i(str, "serverClientId must be provided if Google ID tokens are requested");
            }
            this.b = str;
            this.c = str2;
            this.d = z2;
            ArrayList arrayList2 = null;
            if (arrayList != null && !arrayList.isEmpty()) {
                arrayList2 = new ArrayList(arrayList);
                Collections.sort(arrayList2);
            }
            this.f = arrayList2;
            this.e = str3;
            this.g = z3;
        }

        public static a a() {
            a aVar = new a();
            aVar.a = false;
            aVar.b = null;
            aVar.c = true;
            return aVar;
        }

        public final boolean equals(Object obj) {
            if (!(obj instanceof GoogleIdTokenRequestOptions)) {
                return false;
            }
            GoogleIdTokenRequestOptions googleIdTokenRequestOptions = (GoogleIdTokenRequestOptions) obj;
            return this.a == googleIdTokenRequestOptions.a && u.l(this.b, googleIdTokenRequestOptions.b) && u.l(this.c, googleIdTokenRequestOptions.c) && this.d == googleIdTokenRequestOptions.d && u.l(this.e, googleIdTokenRequestOptions.e) && u.l(this.f, googleIdTokenRequestOptions.f) && this.g == googleIdTokenRequestOptions.g;
        }

        public final int hashCode() {
            Boolean boolValueOf = Boolean.valueOf(this.a);
            Boolean boolValueOf2 = Boolean.valueOf(this.d);
            Boolean boolValueOf3 = Boolean.valueOf(this.g);
            return Arrays.hashCode(new Object[]{boolValueOf, this.b, this.c, boolValueOf2, this.e, this.f, boolValueOf3});
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            int iN = AbstractC3489l3.n(20293, parcel);
            AbstractC3489l3.m(parcel, 1, 4);
            parcel.writeInt(this.a ? 1 : 0);
            AbstractC3489l3.h(parcel, 2, this.b);
            AbstractC3489l3.h(parcel, 3, this.c);
            AbstractC3489l3.m(parcel, 4, 4);
            parcel.writeInt(this.d ? 1 : 0);
            AbstractC3489l3.h(parcel, 5, this.e);
            AbstractC3489l3.j(parcel, 6, this.f);
            AbstractC3489l3.m(parcel, 7, 4);
            parcel.writeInt(this.g ? 1 : 0);
            AbstractC3489l3.o(iN, parcel);
        }
    }

    @Deprecated
    public static final class PasskeyJsonRequestOptions extends AbstractSafeParcelable {

        @NonNull
        public static final Parcelable.Creator<PasskeyJsonRequestOptions> CREATOR = new e();
        public final boolean a;
        public final String b;

        public PasskeyJsonRequestOptions(boolean z, String str) {
            if (z) {
                u.h(str);
            }
            this.a = z;
            this.b = str;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof PasskeyJsonRequestOptions)) {
                return false;
            }
            PasskeyJsonRequestOptions passkeyJsonRequestOptions = (PasskeyJsonRequestOptions) obj;
            return this.a == passkeyJsonRequestOptions.a && u.l(this.b, passkeyJsonRequestOptions.b);
        }

        public final int hashCode() {
            return Arrays.hashCode(new Object[]{Boolean.valueOf(this.a), this.b});
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            int iN = AbstractC3489l3.n(20293, parcel);
            AbstractC3489l3.m(parcel, 1, 4);
            parcel.writeInt(this.a ? 1 : 0);
            AbstractC3489l3.h(parcel, 2, this.b);
            AbstractC3489l3.o(iN, parcel);
        }
    }

    @Deprecated
    public static final class PasskeysRequestOptions extends AbstractSafeParcelable {

        @NonNull
        public static final Parcelable.Creator<PasskeysRequestOptions> CREATOR = new f();
        public final boolean a;
        public final byte[] b;
        public final String c;

        public PasskeysRequestOptions(String str, boolean z, byte[] bArr) {
            if (z) {
                u.h(bArr);
                u.h(str);
            }
            this.a = z;
            this.b = bArr;
            this.c = str;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof PasskeysRequestOptions)) {
                return false;
            }
            PasskeysRequestOptions passkeysRequestOptions = (PasskeysRequestOptions) obj;
            return this.a == passkeysRequestOptions.a && Arrays.equals(this.b, passkeysRequestOptions.b) && Objects.equals(this.c, passkeysRequestOptions.c);
        }

        public final int hashCode() {
            return Arrays.hashCode(this.b) + (Objects.hash(Boolean.valueOf(this.a), this.c) * 31);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            int iN = AbstractC3489l3.n(20293, parcel);
            AbstractC3489l3.m(parcel, 1, 4);
            parcel.writeInt(this.a ? 1 : 0);
            AbstractC3489l3.d(parcel, 2, this.b);
            AbstractC3489l3.h(parcel, 3, this.c);
            AbstractC3489l3.o(iN, parcel);
        }
    }

    @Deprecated
    public static final class PasswordRequestOptions extends AbstractSafeParcelable {

        @NonNull
        public static final Parcelable.Creator<PasswordRequestOptions> CREATOR = new g();
        public final boolean a;

        public PasswordRequestOptions(boolean z) {
            this.a = z;
        }

        public final boolean equals(Object obj) {
            return (obj instanceof PasswordRequestOptions) && this.a == ((PasswordRequestOptions) obj).a;
        }

        public final int hashCode() {
            return Arrays.hashCode(new Object[]{Boolean.valueOf(this.a)});
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            int iN = AbstractC3489l3.n(20293, parcel);
            AbstractC3489l3.m(parcel, 1, 4);
            parcel.writeInt(this.a ? 1 : 0);
            AbstractC3489l3.o(iN, parcel);
        }
    }

    public BeginSignInRequest(PasswordRequestOptions passwordRequestOptions, GoogleIdTokenRequestOptions googleIdTokenRequestOptions, String str, boolean z, int i, PasskeysRequestOptions passkeysRequestOptions, PasskeyJsonRequestOptions passkeyJsonRequestOptions, boolean z2) {
        u.h(passwordRequestOptions);
        this.a = passwordRequestOptions;
        u.h(googleIdTokenRequestOptions);
        this.b = googleIdTokenRequestOptions;
        this.c = str;
        this.d = z;
        this.e = i;
        this.f = passkeysRequestOptions == null ? new PasskeysRequestOptions(null, false, null) : passkeysRequestOptions;
        this.g = passkeyJsonRequestOptions == null ? new PasskeyJsonRequestOptions(false, null) : passkeyJsonRequestOptions;
        this.h = z2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof BeginSignInRequest)) {
            return false;
        }
        BeginSignInRequest beginSignInRequest = (BeginSignInRequest) obj;
        return u.l(this.a, beginSignInRequest.a) && u.l(this.b, beginSignInRequest.b) && u.l(this.f, beginSignInRequest.f) && u.l(this.g, beginSignInRequest.g) && u.l(this.c, beginSignInRequest.c) && this.d == beginSignInRequest.d && this.e == beginSignInRequest.e && this.h == beginSignInRequest.h;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b, this.f, this.g, this.c, Boolean.valueOf(this.d), Integer.valueOf(this.e), Boolean.valueOf(this.h)});
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 1, this.a, i);
        AbstractC3489l3.g(parcel, 2, this.b, i);
        AbstractC3489l3.h(parcel, 3, this.c);
        AbstractC3489l3.m(parcel, 4, 4);
        parcel.writeInt(this.d ? 1 : 0);
        AbstractC3489l3.m(parcel, 5, 4);
        parcel.writeInt(this.e);
        AbstractC3489l3.g(parcel, 6, this.f, i);
        AbstractC3489l3.g(parcel, 7, this.g, i);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.h ? 1 : 0);
        AbstractC3489l3.o(iN, parcel);
    }
}

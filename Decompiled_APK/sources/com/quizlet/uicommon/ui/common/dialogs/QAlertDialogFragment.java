package com.quizlet.uicommon.ui.common.dialogs;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import androidx.compose.animation.d0;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.uicommon.ui.common.dialogs.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QAlertDialogFragment extends DialogInterfaceOnCancelListenerC1151t {
    public static final String t;
    public DialogInterface.OnClickListener q;
    public com.quizlet.quizletandroid.ui.setcreation.fragments.b r;
    public DialogInterface.OnCancelListener s;

    @Metadata
    public static final class DialogData implements Parcelable {

        @NotNull
        public static final Parcelable.Creator<DialogData> CREATOR = new j();
        public final String a;
        public final String b;
        public final String c;
        public final String d;
        public final boolean e;
        public final CharSequence f;

        public DialogData(String message, String str, String str2, String str3, boolean z, CharSequence charSequence) {
            Intrinsics.checkNotNullParameter(message, "message");
            this.a = message;
            this.b = str;
            this.c = str2;
            this.d = str3;
            this.e = z;
            this.f = charSequence;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof DialogData)) {
                return false;
            }
            DialogData dialogData = (DialogData) obj;
            return Intrinsics.b(this.a, dialogData.a) && Intrinsics.b(this.b, dialogData.b) && Intrinsics.b(this.c, dialogData.c) && Intrinsics.b(this.d, dialogData.d) && this.e == dialogData.e && Intrinsics.b(this.f, dialogData.f);
        }

        public final int hashCode() {
            int iHashCode = this.a.hashCode() * 31;
            String str = this.b;
            int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.c;
            int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.d;
            int iG = d0.g((iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31, 31, this.e);
            CharSequence charSequence = this.f;
            return iG + (charSequence != null ? charSequence.hashCode() : 0);
        }

        public final String toString() {
            return "DialogData(message=" + this.a + ", title=" + this.b + ", positiveButtonText=" + this.c + ", negativeButtonText=" + this.d + ", isCancelable=" + this.e + ", messageSpannable=" + ((Object) this.f) + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            dest.writeString(this.b);
            dest.writeString(this.c);
            dest.writeString(this.d);
            dest.writeInt(this.e ? 1 : 0);
            TextUtils.writeToParcel(this.f, dest, i);
        }
    }

    static {
        Intrinsics.checkNotNullExpressionValue("QAlertDialogFragment", "getSimpleName(...)");
        t = "QAlertDialogFragment";
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Parcelable parcelable = requireArguments().getParcelable("textData");
        if (parcelable == null) {
            throw new IllegalArgumentException("Missing argument textData");
        }
        DialogData dialogData = (DialogData) parcelable;
        e.a aVar = new e.a(requireContext());
        CharSequence charSequence = dialogData.f;
        if (charSequence == null) {
            charSequence = dialogData.a;
        }
        aVar.e = charSequence;
        String str = dialogData.b;
        if (str != null) {
            aVar.d = str;
        }
        String str2 = dialogData.c;
        if (str2 != null) {
            final int i = 0;
            f fVar = new f(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.g
                public final /* synthetic */ QAlertDialogFragment b;

                {
                    this.b = this;
                }

                @Override // com.quizlet.uicommon.ui.common.dialogs.f
                public final void c(e eVar, int i2) {
                    switch (i) {
                        case 0:
                            DialogInterface.OnClickListener onClickListener = this.b.q;
                            if (onClickListener == null) {
                                eVar.dismiss();
                                break;
                            } else {
                                onClickListener.onClick(eVar, i2);
                                break;
                            }
                        default:
                            com.quizlet.quizletandroid.ui.setcreation.fragments.b bVar = this.b.r;
                            if (bVar == null) {
                                eVar.dismiss();
                                break;
                            } else {
                                bVar.onClick(eVar, i2);
                                break;
                            }
                    }
                }
            };
            aVar.i = str2;
            aVar.j = fVar;
        }
        String str3 = dialogData.d;
        if (str3 != null) {
            final int i2 = 1;
            f fVar2 = new f(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.g
                public final /* synthetic */ QAlertDialogFragment b;

                {
                    this.b = this;
                }

                @Override // com.quizlet.uicommon.ui.common.dialogs.f
                public final void c(e eVar, int i22) {
                    switch (i2) {
                        case 0:
                            DialogInterface.OnClickListener onClickListener = this.b.q;
                            if (onClickListener == null) {
                                eVar.dismiss();
                                break;
                            } else {
                                onClickListener.onClick(eVar, i22);
                                break;
                            }
                        default:
                            com.quizlet.quizletandroid.ui.setcreation.fragments.b bVar = this.b.r;
                            if (bVar == null) {
                                eVar.dismiss();
                                break;
                            } else {
                                bVar.onClick(eVar, i22);
                                break;
                            }
                    }
                }
            };
            aVar.k = str3;
            aVar.l = fVar2;
        }
        aVar.b = dialogData.e;
        aVar.c = this.s;
        e eVarB = aVar.b();
        Intrinsics.checkNotNullExpressionValue(eVarB, "create(...)");
        return eVarB;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        DialogInterface.OnCancelListener onCancelListener = this.s;
        if (onCancelListener != null) {
            onCancelListener.onCancel(dialog);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Parcelable parcelable = requireArguments().getParcelable("textData");
        if (parcelable == null) {
            throw new IllegalArgumentException("Missing argument textData");
        }
        boolean z = ((DialogData) parcelable).e;
        this.g = z;
        Dialog dialog = this.l;
        if (dialog != null) {
            dialog.setCancelable(z);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.q = null;
        this.r = null;
        this.s = null;
        super.onDestroyView();
    }
}

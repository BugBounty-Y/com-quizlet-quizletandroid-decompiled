package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.content.res.Resources;
import android.widget.CompoundButton;
import androidx.appcompat.widget.SwitchCompat;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3681n4;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class p implements CompoundButton.OnCheckedChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ p(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.widget.CompoundButton.OnCheckedChangeListener
    public final void onCheckedChanged(CompoundButton compoundButton, boolean z) throws Resources.NotFoundException {
        Context contextRequireContext;
        SwitchCompat switchCompat;
        String str;
        String str2;
        Context contextRequireContext2;
        String str3;
        String str4;
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                q this$0 = (q) obj2;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                com.onetrust.otpublishers.headless.UI.DataModels.g item = (com.onetrust.otpublishers.headless.UI.DataModels.g) obj;
                Intrinsics.checkNotNullParameter(item, "$item");
                this$0.g.invoke(item.a, Boolean.valueOf(z));
                SwitchCompat switchCompat2 = (SwitchCompat) this$0.a.c;
                com.onetrust.otpublishers.headless.UI.DataModels.i iVar = this$0.b;
                String str5 = z ? iVar.g : iVar.h;
                Intrinsics.checkNotNullExpressionValue(switchCompat2, "");
                AbstractC3681n4.a(switchCompat2, iVar.i, str5);
                break;
            case 1:
                D this$02 = (D) obj2;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                com.onetrust.otpublishers.headless.UI.DataModels.j item2 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj;
                Intrinsics.checkNotNullParameter(item2, "$item");
                this$02.d.invoke(item2.a, Boolean.valueOf(z));
                this$02.c(z);
                break;
            case 2:
                J this$03 = (J) obj2;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                com.onetrust.otpublishers.headless.UI.DataModels.j item3 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj;
                Intrinsics.checkNotNullParameter(item3, "$item");
                this$03.e.invoke(item3.a, Boolean.valueOf(z));
                this$03.c(z);
                break;
            case 3:
                L this$04 = (L) obj2;
                Intrinsics.checkNotNullParameter(this$04, "this$0");
                com.onetrust.otpublishers.headless.UI.DataModels.j item4 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj;
                Intrinsics.checkNotNullParameter(item4, "$item");
                this$04.d.invoke(item4.a, Boolean.valueOf(z));
                SwitchCompat switchCompat3 = (SwitchCompat) this$04.a.e;
                com.onetrust.otpublishers.headless.UI.DataModels.l lVar = this$04.b;
                String str6 = z ? lVar.g : lVar.h;
                Intrinsics.checkNotNullExpressionValue(switchCompat3, "");
                AbstractC3681n4.a(switchCompat3, lVar.f, str6);
                break;
            case 4:
                com.onetrust.otpublishers.headless.UI.fragment.s this$05 = (com.onetrust.otpublishers.headless.UI.fragment.s) obj2;
                Intrinsics.checkNotNullParameter(this$05, "this$0");
                com.onetrust.otpublishers.headless.UI.DataModels.i sdkListData = (com.onetrust.otpublishers.headless.UI.DataModels.i) obj;
                Intrinsics.checkNotNullParameter(sdkListData, "$sdkListData");
                com.onetrust.otpublishers.headless.databinding.b bVar = this$05.q;
                Intrinsics.d(bVar);
                com.onetrust.otpublishers.headless.databinding.f fVar = (com.onetrust.otpublishers.headless.databinding.f) bVar.d;
                if (z) {
                    contextRequireContext = this$05.requireContext();
                    switchCompat = fVar.f;
                    str = sdkListData.i;
                    str2 = sdkListData.g;
                } else {
                    contextRequireContext = this$05.requireContext();
                    switchCompat = fVar.f;
                    str = sdkListData.i;
                    str2 = sdkListData.h;
                }
                this$05.u.getClass();
                assistantMode.utils.studiableMetadata.b.s(contextRequireContext, switchCompat, str, str2);
                break;
            default:
                com.google.firebase.perf.logging.b bVar2 = com.onetrust.otpublishers.headless.UI.fragment.D.D;
                com.onetrust.otpublishers.headless.UI.fragment.D this$06 = (com.onetrust.otpublishers.headless.UI.fragment.D) obj2;
                Intrinsics.checkNotNullParameter(this$06, "this$0");
                com.onetrust.otpublishers.headless.UI.DataModels.l vendorListData = (com.onetrust.otpublishers.headless.UI.DataModels.l) obj;
                Intrinsics.checkNotNullParameter(vendorListData, "$vendorListData");
                OTLogger.c("OneTrust", 3, "onCreateViewSetOnCheckedChangeListener " + z);
                SwitchCompat switchCompat4 = (SwitchCompat) this$06.Q().b.h;
                if (z) {
                    contextRequireContext2 = this$06.requireContext();
                    str3 = vendorListData.f;
                    str4 = vendorListData.g;
                } else {
                    contextRequireContext2 = this$06.requireContext();
                    str3 = vendorListData.f;
                    str4 = vendorListData.h;
                }
                this$06.u.getClass();
                assistantMode.utils.studiableMetadata.b.s(contextRequireContext2, switchCompat4, str3, str4);
                break;
        }
    }
}

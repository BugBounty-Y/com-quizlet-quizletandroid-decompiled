package com.braze.ui.actions.brazeactions;

import android.net.Uri;
import com.braze.models.cards.Card;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.inappmessage.IInAppMessageImmersive;
import com.braze.models.inappmessage.MessageButton;
import com.braze.ui.actions.brazeactions.BrazeActionParser;
import com.braze.ui.actions.brazeactions.steps.ContainerStep;
import com.braze.ui.actions.brazeactions.steps.StepData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public abstract class BrazeActionUtils {

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[BrazeActionParser.ActionType.values().length];
            try {
                iArr[BrazeActionParser.ActionType.CONTAINER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public static final boolean containsAnyPushPermissionBrazeActions(@NotNull IInAppMessage iInAppMessage) {
        Intrinsics.checkNotNullParameter(iInAppMessage, "<this>");
        return doAnyTypesMatch(BrazeActionParser.ActionType.REQUEST_PUSH_PERMISSION, getAllUris(iInAppMessage));
    }

    public static final boolean containsInvalidBrazeAction(@NotNull IInAppMessage iInAppMessage) {
        Intrinsics.checkNotNullParameter(iInAppMessage, "<this>");
        return doAnyTypesMatch(BrazeActionParser.ActionType.INVALID, getAllUris(iInAppMessage));
    }

    public static final boolean doAnyTypesMatch(@NotNull BrazeActionParser.ActionType actionType, @NotNull List<? extends Uri> uriList) {
        JSONObject jSONObject;
        Intrinsics.checkNotNullParameter(actionType, "actionType");
        Intrinsics.checkNotNullParameter(uriList, "uriList");
        ArrayList arrayList = new ArrayList();
        for (Object obj : uriList) {
            if (BrazeActionParser.INSTANCE.isBrazeActionUri((Uri) obj)) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Pair brazeActionVersionAndJson$android_sdk_ui_release = BrazeActionParser.INSTANCE.getBrazeActionVersionAndJson$android_sdk_ui_release((Uri) it2.next());
            if (brazeActionVersionAndJson$android_sdk_ui_release == null || (jSONObject = (JSONObject) brazeActionVersionAndJson$android_sdk_ui_release.b) == null) {
                jSONObject = new JSONObject();
            }
            arrayList2.add(jSONObject);
        }
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            G.u(arrayList3, getAllBrazeActionStepTypes((JSONObject) it3.next()));
        }
        if (arrayList3.isEmpty()) {
            return false;
        }
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            if (((BrazeActionParser.ActionType) it4.next()) == actionType) {
                return true;
            }
        }
        return false;
    }

    public static final /* synthetic */ List getAllBrazeActionStepTypes(JSONObject json) {
        Intrinsics.checkNotNullParameter(json, "json");
        ArrayList arrayList = new ArrayList();
        StepData stepData = new StepData(json, null, 2, null);
        BrazeActionParser.ActionType actionType$android_sdk_ui_release = BrazeActionParser.INSTANCE.getActionType$android_sdk_ui_release(stepData);
        if (WhenMappings.$EnumSwitchMapping$0[actionType$android_sdk_ui_release.ordinal()] != 1) {
            arrayList.add(actionType$android_sdk_ui_release);
            return arrayList;
        }
        Iterator childStepIterator$android_sdk_ui_release = ContainerStep.INSTANCE.getChildStepIterator$android_sdk_ui_release(stepData);
        while (childStepIterator$android_sdk_ui_release.hasNext()) {
            arrayList.addAll(getAllBrazeActionStepTypes((JSONObject) childStepIterator$android_sdk_ui_release.next()));
        }
        return arrayList;
    }

    public static final List getAllUris(IInAppMessage iInAppMessage) {
        if (iInAppMessage == null) {
            return K.a;
        }
        ArrayList arrayList = new ArrayList();
        Uri uri = iInAppMessage.getUri();
        if (uri != null) {
            arrayList.add(uri);
        }
        if (iInAppMessage instanceof IInAppMessageImmersive) {
            List<MessageButton> messageButtons = ((IInAppMessageImmersive) iInAppMessage).getMessageButtons();
            ArrayList arrayList2 = new ArrayList();
            Iterator<T> it2 = messageButtons.iterator();
            while (it2.hasNext()) {
                Uri uri2 = ((MessageButton) it2.next()).getUri();
                if (uri2 != null) {
                    arrayList2.add(uri2);
                }
            }
            arrayList.addAll(arrayList2);
        }
        return arrayList;
    }

    public static final boolean containsInvalidBrazeAction(@NotNull Card card) {
        Intrinsics.checkNotNullParameter(card, "<this>");
        if (card.getUrl() != null) {
            return doAnyTypesMatch(BrazeActionParser.ActionType.INVALID, A.b(Uri.parse(card.getUrl())));
        }
        return false;
    }
}

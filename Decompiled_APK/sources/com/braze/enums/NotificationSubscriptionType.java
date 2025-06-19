package com.braze.enums;

import androidx.compose.ui.node.B;
import com.braze.models.IPutIntoJson;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.U;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class NotificationSubscriptionType implements IPutIntoJson<String> {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ NotificationSubscriptionType[] $VALUES;
    public static final Companion Companion;
    public static final NotificationSubscriptionType OPTED_IN = new NotificationSubscriptionType("OPTED_IN", 0, "opted_in");
    public static final NotificationSubscriptionType SUBSCRIBED = new NotificationSubscriptionType("SUBSCRIBED", 1, "subscribed");
    public static final NotificationSubscriptionType UNSUBSCRIBED = new NotificationSubscriptionType("UNSUBSCRIBED", 2, "unsubscribed");
    private static final Map<String, NotificationSubscriptionType> map;
    private final String key;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final NotificationSubscriptionType fromValue(String str) {
            String strK;
            Map map = NotificationSubscriptionType.map;
            if (str != null) {
                Locale locale = Locale.US;
                strK = B.k(locale, "US", str, locale, "toLowerCase(...)");
            } else {
                strK = null;
            }
            if (strK == null) {
                strK = "";
            }
            Object obj = map.get(strK);
            return (NotificationSubscriptionType) (obj != null ? obj : null);
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ NotificationSubscriptionType[] $values() {
        return new NotificationSubscriptionType[]{OPTED_IN, SUBSCRIBED, UNSUBSCRIBED};
    }

    static {
        NotificationSubscriptionType[] notificationSubscriptionTypeArr$values = $values();
        $VALUES = notificationSubscriptionTypeArr$values;
        $ENTRIES = AbstractC3328d.f(notificationSubscriptionTypeArr$values);
        Companion = new Companion(null);
        NotificationSubscriptionType[] notificationSubscriptionTypeArrValues = values();
        int iA = U.a(notificationSubscriptionTypeArrValues.length);
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA < 16 ? 16 : iA);
        for (NotificationSubscriptionType notificationSubscriptionType : notificationSubscriptionTypeArrValues) {
            linkedHashMap.put(notificationSubscriptionType.key, notificationSubscriptionType);
        }
        map = linkedHashMap;
    }

    private NotificationSubscriptionType(String str, int i, String str2) {
        this.key = str2;
    }

    public static NotificationSubscriptionType valueOf(String str) {
        return (NotificationSubscriptionType) Enum.valueOf(NotificationSubscriptionType.class, str);
    }

    public static NotificationSubscriptionType[] values() {
        return (NotificationSubscriptionType[]) $VALUES.clone();
    }

    @Override // com.braze.models.IPutIntoJson
    public String forJsonPut() {
        return this.key;
    }
}

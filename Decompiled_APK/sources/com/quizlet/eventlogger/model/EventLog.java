package com.quizlet.eventlogger.model;

import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.generated.enums.EnumC4503n;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Date;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.enums.a;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Metadata
/* loaded from: classes2.dex */
public abstract class EventLog {
    public static final Companion a = new Companion(null);
    private EnumC4503n table;

    @JsonProperty("eventName")
    @NotNull
    private String action = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;

    @JsonDeserialize(using = DateDeserializer.class)
    @JsonSerialize(using = DateSerializer.class)
    @NotNull
    private Date timestamp = new Date();

    @Metadata
    @Retention(RetentionPolicy.SOURCE)
    public @interface Action {

        @Metadata
        public static final class Companion {
            static {
                new Companion();
            }

            private Companion() {
            }
        }
    }

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class DateDeserializer extends JsonDeserializer<Date> {
        @Override // com.fasterxml.jackson.databind.JsonDeserializer
        public final Date deserialize(JsonParser p, DeserializationContext ctxt) {
            Intrinsics.checkNotNullParameter(p, "p");
            Intrinsics.checkNotNullParameter(ctxt, "ctxt");
            return new Date(p.getValueAsLong() * 1000);
        }
    }

    @Metadata
    public static final class DateSerializer extends JsonSerializer<Date> {
        @Override // com.fasterxml.jackson.databind.JsonSerializer
        public final void serialize(Date date, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            Date date2 = date;
            Intrinsics.checkNotNullParameter(date2, "date");
            Intrinsics.checkNotNullParameter(gen, "gen");
            Intrinsics.checkNotNullParameter(serializers, "serializers");
            gen.writeNumber(date2.getTime() / 1000);
        }
    }

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class DiskSpace {
        private static final /* synthetic */ a $ENTRIES;
        private static final /* synthetic */ DiskSpace[] $VALUES;
        public static final DiskSpace a;
        public static final DiskSpace b;
        public static final DiskSpace c;
        public static final DiskSpace d;

        @NotNull
        private final String value;

        static {
            DiskSpace diskSpace = new DiskSpace("DOWNLOAD_IMAGES_DISK_SPACE", 0, "download_images_disk_space");
            a = diskSpace;
            DiskSpace diskSpace2 = new DiskSpace("DOWNLOAD_AUDIO_DISK_SPACE", 1, "download_audio_disk_space");
            b = diskSpace2;
            DiskSpace diskSpace3 = new DiskSpace("DATABASE_DISK_SPACE", 2, "database_disk_space");
            c = diskSpace3;
            DiskSpace diskSpace4 = new DiskSpace("OTHER_DISK_SPACE", 3, "other_disk_space");
            d = diskSpace4;
            DiskSpace[] diskSpaceArr = {diskSpace, diskSpace2, diskSpace3, diskSpace4};
            $VALUES = diskSpaceArr;
            $ENTRIES = AbstractC3328d.f(diskSpaceArr);
        }

        private DiskSpace(String str, int i, String str2) {
            this.value = str2;
        }

        @NotNull
        public static a getEntries() {
            return $ENTRIES;
        }

        public static DiskSpace valueOf(String str) {
            return (DiskSpace) Enum.valueOf(DiskSpace.class, str);
        }

        public static DiskSpace[] values() {
            return (DiskSpace[]) $VALUES.clone();
        }

        @NotNull
        public final String getValue() {
            return this.value;
        }
    }

    public abstract void a(UUID uuid, UUID uuid2, Boolean bool, CurrentUserEvent currentUserEvent);

    public void b(boolean z, boolean z2) {
    }

    @JsonIgnore
    @NotNull
    public final String getAction() {
        return this.action;
    }

    public final EnumC4503n getTable() {
        return this.table;
    }

    @JsonGetter("table")
    public final String getTableValue() {
        EnumC4503n enumC4503n = this.table;
        if (enumC4503n != null) {
            return enumC4503n.a();
        }
        return null;
    }

    @JsonIgnore
    @NotNull
    public final Date getTimestamp() {
        return this.timestamp;
    }

    public final void setAction(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.action = str;
    }

    public final void setTable(EnumC4503n enumC4503n) {
        this.table = enumC4503n;
    }

    @JsonSetter("table")
    public final void setTableValue(String str) {
        EnumC4503n enumC4503n;
        EnumC4503n.Companion.getClass();
        EnumC4503n[] enumC4503nArrValues = EnumC4503n.values();
        int length = enumC4503nArrValues.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                enumC4503n = null;
                break;
            }
            enumC4503n = enumC4503nArrValues[i];
            if (Intrinsics.b(enumC4503n.a(), str)) {
                break;
            } else {
                i++;
            }
        }
        this.table = enumC4503n;
    }

    public final void setTimestamp(@NotNull Date date) {
        Intrinsics.checkNotNullParameter(date, "<set-?>");
        this.timestamp = date;
    }

    public final void setTimestampMs(long j) {
        this.timestamp = new Date(j);
    }
}

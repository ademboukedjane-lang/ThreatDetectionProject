package threatdetector.model;

import java.util.Objects;

public class ScanItem {

	  private final int id;
	    private final InputType type;
	    private final String content;

	    public ScanItem(int id, InputType type, String content) {
	        this.id = id;
	        this.type = Objects.requireNonNull(type, "type");
	        this.content = content == null ? "" : content;
	    }

	    public int getId() { return id; }
	    public InputType getType() { return type; }
	    public String getContent() { return content; }

	    @Override
	    public String toString() {
	        return "ScanItem{id=" + id + ", type=" + type + ", content='" + content + "'}";
	    }
}

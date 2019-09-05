#
# This is an example script that can be used as
# pwman -p examplescript.py
# pwman --call-pymod examplescript.py
#
# See pwman --help for more information about the command line options.
# See doc/api/ for a description of the Python API.
#

# Entry point.
# The 'db' parameter is a PWManDatabase instance.
# See doc/api/libpwman/database.html
def run(db):
	# Print all category names.
	categories = db.getCategoryNames()
	print("Categories:", categories)

	# Print all titles in a category.
	titles = db.getEntryTitles("testcat1")
	print("Titles in testcat1:", titles)

	# Move all titles from a category to another one and change the title.
	for title in titles:
		entry = db.getEntry("testcat1", title)
		print("Moving entry:", entry)
		db.moveEntry(entry, "othercat", "foobar_" + title)

	# Permanently write the changes to the database file.
	db.commit()

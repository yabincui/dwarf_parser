""" build format table """


def generate_attr_table():
    with open('temp', 'r') as fh:
        data = fh.read()
    for line in data.split('\n'):
        line = line.strip()
        if not line:
            continue
        items = line.split()
        #print "%s = %s" % (items[0], items[1])
        print "    %s : '%s'," % (items[1], items[0])


def main():
    generate_attr_table()

main()
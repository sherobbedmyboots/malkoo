# create a new repository on the command line
echo "# malkoo" >> README.md
git init
git add README.md
git commit -m "first commit"
git remote add origin git@github.com:<user>/<repo>.git
git push -u origin master

# Push an existing repository
git remote add origin git@github.com:<user>/<repo>.git
git remote set-url origin git@github.com:<user>/<repo>.git
git push -u origin master

# create branch and check out
git checkout -b fix-issue

# key
eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_rsa_